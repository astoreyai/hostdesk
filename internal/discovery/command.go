package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/astoreyai/hostdesk/internal/model"
)

const commandLimit = 8 << 20

// Commands never inherit engine remote endpoints, credentials, or the caller's PATH.
// User D-Bus needs its session address; privileged collection deliberately omits it.
func commandEnvironment() []string {
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C", "LANG=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	if os.Geteuid() == 0 {
		return append(env, "HOME=/root")
	}
	for _, key := range []string{"HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func executable(name string) (string, error) {
	if filepath.Base(name) != name {
		return "", errors.New("invalid executable")
	}
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"} {
		path, err := filepath.EvalSymlinks(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			continue
		}
		if os.Geteuid() == 0 {
			trusted := true
			for current := path; ; current = filepath.Dir(current) {
				st, err := os.Stat(current)
				if err != nil {
					trusted = false
					break
				}
				sys, ok := st.Sys().(*syscall.Stat_t)
				if !ok || sys.Uid != 0 || st.Mode().Perm()&0022 != 0 {
					trusted = false
					break
				}
				if current == "/" {
					break
				}
			}
			if !trusted {
				continue
			}
		}
		return path, nil
	}
	return "", fmt.Errorf("%s is unavailable in trusted executable directories", name)
}

type boundedOutput struct {
	bytes.Buffer
	exceeded bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := commandLimit - b.Len()
	if n > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := executable(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	// Keep multicall dispatch (e.g. iptables-save -> xtables-nft-multi)
	// while executing the separately resolved and validated binary path.
	cmd.Args[0] = name
	cmd.Env = commandEnvironment()
	cmd.WaitDelay = time.Second
	var stdout boundedOutput
	cmd.Stdout = &stdout
	// Tool errors can echo command arguments, credentials or generated descriptions.
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if ctx.Err() != nil {
		return stdout.Bytes(), fmt.Errorf("%s collection deadline exceeded or canceled", name)
	}
	if stdout.exceeded {
		return stdout.Bytes(), fmt.Errorf("%s output exceeded collection limit", name)
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return stdout.Bytes(), fmt.Errorf("%s exited with status %d; permissions, daemon availability or configuration may prevent collection", name, exit.ExitCode())
		}
		return stdout.Bytes(), fmt.Errorf("%s could not be executed", name)
	}
	return stdout.Bytes(), nil
}

func source(name string, err error) model.Source {
	s := model.Source{Name: name, Available: err == nil, CheckedAt: time.Now().UTC()}
	if err != nil {
		s.Error = err.Error()
	}
	return s
}

func partial(s *model.Source, message string) {
	if strings.Contains(s.Error, message) || len(s.Error) >= 2048 {
		return
	}
	if s.Error != "" {
		s.Error += "; "
	}
	s.Error += message
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular readable file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeded collection limit")
	}
	return data, err
}

func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}
