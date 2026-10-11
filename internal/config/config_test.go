package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		Listen:         "127.0.0.1:0",
		StateDir:       filepath.Join(dir, "state"),
		BrokerSocket:   filepath.Join(dir, "broker.sock"),
		ProjectRoots:   []string{dir},
		RefreshSeconds: 15,
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*Config)
		wantErr bool
	}{
		{"numeric IPv4 loopback", func(c *Config) { c.Listen = "127.0.0.1:8080" }, false},
		{"numeric IPv6 loopback", func(c *Config) { c.Listen = "[::1]:8080" }, false},
		{"non-loopback", func(c *Config) { c.Listen = "192.0.2.1:8080" }, true},
		{"wildcard", func(c *Config) { c.Listen = "0.0.0.0:8080" }, true},
		{"hostname", func(c *Config) { c.Listen = "localhost:8080" }, true},
		{"missing port", func(c *Config) { c.Listen = "127.0.0.1" }, true},
		{"relative state directory", func(c *Config) { c.StateDir = "state" }, true},
		{"refresh below minimum", func(c *Config) { c.RefreshSeconds = 1 }, true},
		{"refresh minimum", func(c *Config) { c.RefreshSeconds = 2 }, false},
		{"refresh maximum", func(c *Config) { c.RefreshSeconds = 3600 }, false},
		{"refresh above maximum", func(c *Config) { c.RefreshSeconds = 3601 }, true},
		{"relative broker socket", func(c *Config) { c.BrokerSocket = "broker.sock" }, true},
		{"optional broker socket", func(c *Config) { c.BrokerSocket = "" }, false},
		{"relative project root", func(c *Config) { c.ProjectRoots = append(c.ProjectRoots, "projects") }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			tt.change(&cfg)
			if err := Validate(cfg); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePathControlCharacters(t *testing.T) {
	fields := []struct {
		name          string
		appendControl func(*Config, string)
	}{
		{"stateDir", func(c *Config, control string) { c.StateDir += control }},
		{"brokerSocket", func(c *Config, control string) { c.BrokerSocket += control }},
		{"projectRoots", func(c *Config, control string) { c.ProjectRoots[0] += control }},
	}
	for _, field := range fields {
		for _, control := range []struct{ name, value string }{
			{"NUL", "\x00"}, {"CR", "\r"}, {"LF", "\n"},
		} {
			t.Run(field.name+"/"+control.name, func(t *testing.T) {
				cfg := validConfig(t)
				field.appendControl(&cfg, control.value)
				if err := Validate(cfg); err == nil {
					t.Fatal("Validate() accepted a control character in a path")
				}
			})
		}
	}
}

func TestValidateExternalOrigin(t *testing.T) {
	for _, tt := range []struct {
		name, origin string
		wantErr      bool
	}{
		{"HTTPS origin", "https://host", false},
		{"HTTP scheme", "http://host", true},
		{"credentials", "https://user:password@host", true},
		{"path", "https://host/desk", true},
		{"query", "https://host?desk=1", true},
		{"fragment", "https://host#desk", true},
		{"trailing slash", "https://host/", true},
		{"missing host", "https://", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.ExternalOrigin = tt.origin
			if err := Validate(cfg); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTailscaleRequiresExternalOrigin(t *testing.T) {
	cfg := validConfig(t)
	cfg.AllowedTailscaleUsers = []string{"owner@example.com"}
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() accepted Tailscale identities without externalOrigin")
	}
	cfg.ExternalOrigin = "https://host"
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() with externalOrigin: %v", err)
	}
}

func TestLoadRejectsPublicPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0640, 0604, 0644} {
		t.Run(mode.String(), func(t *testing.T) {
			cfg := validConfig(t)
			path := filepath.Join(t.TempDir(), "private", "config.json")
			if err := Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load() accepted permissions %04o", mode)
			}
		})
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	cfg := validConfig(t)
	cfg.ExternalOrigin = "https://host"
	cfg.AllowedTailscaleUsers = []string{"owner@example.com"}
	path := filepath.Join(t.TempDir(), "private", "config.json")
	for _, refresh := range []int{2, 3600} {
		cfg.RefreshSeconds = refresh
		if err := Save(path, cfg); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("file mode = %04o, want 0600", got)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, cfg) {
			t.Fatalf("Load() = %#v, want %#v", got, cfg)
		}
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("directory mode = %04o, want 0700", got)
	}
}

func TestWritePrivateJSONRejectsPublicPaths(t *testing.T) {
	for _, publicDirectory := range []bool{false, true} {
		name := "public file"
		if publicDirectory {
			name = "public directory"
		}
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.json")
			original, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			target, mode := path, os.FileMode(0644)
			if publicDirectory {
				target, mode = dir, 0755
			}
			if err := os.Chmod(target, mode); err != nil {
				t.Fatal(err)
			}
			cfg.RefreshSeconds = 30
			if err := WritePrivateJSON(path, cfg); err == nil {
				t.Fatal("WritePrivateJSON() accepted a public path")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(original) {
				t.Fatal("WritePrivateJSON() modified the existing file on rejection")
			}
		})
	}
}
