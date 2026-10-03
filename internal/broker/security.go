package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const commandPath = "/usr/sbin:/usr/bin:/sbin:/bin"
const maxCommandOutput = 8 << 20

// Error preserves the broker's safe, public error classification across the socket.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"error"`
}

func (e *Error) Error() string { return e.Message }
func failure(status int, code, message string) error {
	return &Error{Status: status, Code: code, Message: message}
}
func unavailable(message string) error { return failure(503, "unavailable", message) }
func invalid(message string) error     { return failure(400, "validation", message) }
func (e *Error) StatusCode() int       { return e.Status }
func (e *Error) ErrorCode() string     { return e.Code }
func stale(message string) error       { return failure(409, "stale", message) }
func forbidden(message string) error   { return failure(403, "forbidden", message) }

func randomToken() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func validateActor(actor string) error {
	if actor == "" || len(actor) > 256 || strings.IndexFunc(actor, unicode.IsControl) >= 0 {
		return invalid("invalid actor")
	}
	return nil
}

// Walk every component: checking only the leaf permits replacing a trusted file
// through an untrusted ancestor. State and policy paths intentionally reject links.
func rootPath(path string, directory bool, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path must be absolute and clean")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("path is not root-controlled")
		}
		leaf := i == len(parts)-1
		if (!leaf || directory) && !info.IsDir() {
			return fmt.Errorf("path component is not a directory")
		}
		if leaf && !directory && (!info.Mode().IsRegular() || stat.Nlink != 1) {
			return fmt.Errorf("file must be a regular, singly-linked file")
		}
		if leaf && private && info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("private state permissions are too broad")
		}
	}
	return nil
}

func ensureRootDir(path string, private bool) error {
	if err := rootPath(path, true, private); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("directory path must be absolute and clean")
	}
	parent := filepath.Dir(path)
	if parent == path {
		return fmt.Errorf("invalid state directory")
	}
	if err := ensureRootDir(parent, false); err != nil {
		return err
	}
	mode := os.FileMode(0755)
	if private {
		mode = 0700
	}
	if err := os.Mkdir(path, mode); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
	} else if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return rootPath(path, true, private)
}

func openPrivate(path string, flags int) (*os.File, error) {
	if err := rootPath(filepath.Dir(path), true, true); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
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
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, fmt.Errorf("insecure private file")
	}
	return file, nil
}

func safeExecutable(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return "", unavailable("invalid executable")
	}
	for _, dir := range strings.Split(commandPath, ":") {
		path, err := filepath.EvalSymlinks(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if err := rootPath(path, false, false); err != nil {
			continue
		}
		info, err := os.Stat(path)
		if err == nil && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", unavailable(name + " is not available as a trusted executable")
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, fmt.Errorf("command output exceeded limit")
	}
	return b.Buffer.Write(p)
}

func run(ctx context.Context, name string, input string, args ...string) ([]byte, error) {
	path, err := safeExecutable(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Args[0] = name
	cmd.Env = []string{"PATH=" + commandPath, "HOME=/root", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out := &boundedOutput{limit: maxCommandOutput}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, unavailable(name + " command failed; inspect the host's local service logs")
	}
	return out.Bytes(), nil
}
