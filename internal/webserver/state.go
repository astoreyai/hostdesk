package webserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func prepareState(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("stateDir must be an absolute path")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create private state: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return errors.New("stateDir must be an owner-only directory owned by the serving user")
	}
	return nil
}

func openPrivate(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0600 || stat.Nlink != 1 {
		file.Close()
		return nil, errors.New("private state file must be regular, owner-owned, mode 0600, and not hard-linked")
	}
	return file, nil
}

func lockState(dir string) (*os.File, error) {
	f, err := openPrivate(filepath.Join(dir, "server.lock"), syscall.O_RDWR|syscall.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another server is already using this state directory")
	}
	return f, nil
}

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func ownerToken(dir string) (string, error) {
	path := filepath.Join(dir, "token")
	file, err := openPrivate(path, syscall.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		token, err := randomToken()
		if err != nil {
			return "", err
		}
		if err := writePrivateBytes(path, []byte(token+"\n")); err != nil {
			return "", err
		}
		return token, nil
	}
	if err != nil {
		return "", fmt.Errorf("open owner token: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return "", err
	}
	token := strings.TrimSuffix(string(data), "\n")
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || len(token) != 43 {
		return "", errors.New("owner token file is invalid")
	}
	return token, nil
}

func writePrivateJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writePrivateBytes(path, append(data, '\n'))
}

// Same-directory rename plus fsync makes the published runtime state survive a
// crash without readers seeing a truncated token, address, or audit snapshot.
func writePrivateBytes(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".hostdesk-state-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func persistedListen(dir, configured string) (string, error) {
	host, port, err := net.SplitHostPort(configured)
	if err != nil || port != "0" {
		return configured, err
	}
	file, err := openPrivate(filepath.Join(dir, "listen.json"), syscall.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return configured, nil
	}
	if err != nil {
		return "", fmt.Errorf("read previous listen address: %w", err)
	}
	defer file.Close()
	var saved struct {
		Address string `json:"address"`
		Origin  string `json:"origin"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&saved); err != nil {
		return "", errors.New("previous listen state is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "", errors.New("previous listen state contains trailing data")
	}
	previousHost, previousPort, err := net.SplitHostPort(saved.Address)
	parsedPort, portErr := strconv.Atoi(previousPort)
	ip := net.ParseIP(previousHost)
	if err != nil || portErr != nil || parsedPort < 1 || parsedPort > 65535 || ip == nil || !ip.IsLoopback() || saved.Origin != "http://"+saved.Address {
		return "", errors.New("previous listen state is not a valid loopback endpoint")
	}
	// Reuse the selected port, retaining the operator's explicitly chosen IP.
	// A collision fails startup rather than silently stranding a proxy route.
	return net.JoinHostPort(host, previousPort), nil
}
