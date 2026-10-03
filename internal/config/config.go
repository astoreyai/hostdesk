package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func DefaultPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "hostdesk", "config.json"), nil
}

func Defaults() (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, err
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		state = filepath.Join(home, ".local", "state")
	}
	roots := []string{}
	for _, name := range []string{"projects", "Projects", "src", "code"} {
		p := filepath.Join(home, name)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			roots = append(roots, p)
		}
	}
	return Config{Listen: "127.0.0.1:0", StateDir: filepath.Join(state, "hostdesk"), ProjectRoots: roots, AllowedTailscaleUsers: []string{}, RefreshSeconds: 15}, nil
}

func Load(path string) (Config, error) {
	var cfg Config
	info, err := os.Lstat(path)
	if err != nil {
		return cfg, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return cfg, errors.New("configuration must be a private regular file (mode 0600)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("decode configuration: %w", err)
	}
	return cfg, Validate(cfg)
}

func Validate(cfg Config) error {
	for _, path := range append([]string{cfg.StateDir, cfg.BrokerSocket}, cfg.ProjectRoots...) {
		if strings.ContainsAny(path, "\x00\r\n") {
			return errors.New("paths must not contain control characters")
		}
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen must use a numeric loopback IP")
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return errors.New("stateDir must be absolute")
	}
	if cfg.RefreshSeconds < 2 || cfg.RefreshSeconds > 3600 {
		return errors.New("refreshSeconds must be between 2 and 3600")
	}
	if cfg.BrokerSocket != "" && !filepath.IsAbs(cfg.BrokerSocket) {
		return errors.New("brokerSocket must be absolute")
	}
	for _, root := range cfg.ProjectRoots {
		if !filepath.IsAbs(root) {
			return errors.New("project roots must be absolute")
		}
	}
	if cfg.ExternalOrigin != "" {
		u, e := url.Parse(cfg.ExternalOrigin)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("externalOrigin must be an HTTPS origin without credentials, query or path")
		}
		if strings.HasSuffix(cfg.ExternalOrigin, "/") {
			return errors.New("externalOrigin must not end with a slash")
		}
	}
	if len(cfg.AllowedTailscaleUsers) > 0 && cfg.ExternalOrigin == "" {
		return errors.New("Tailscale identities require externalOrigin")
	}
	for _, user := range cfg.AllowedTailscaleUsers {
		if user == "" || strings.TrimSpace(user) != user || strings.ContainsAny(user, "\r\n\x00") {
			return errors.New("invalid Tailscale login")
		}
	}
	return nil
}

func Save(path string, cfg Config) error {
	if err := Validate(cfg); err != nil {
		return err
	}
	return WritePrivateJSON(path, cfg)
}

func WritePrivateJSON(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private directory required: %s", dir)
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return errors.New("refusing to replace non-private configuration")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".hostdesk-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(b, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
