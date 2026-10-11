package discovery

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestExposure(t *testing.T) {
	cases := []struct {
		address string
		want    string
	}{
		{"127.0.0.1", "loopback"},
		{"127.255.255.254", "loopback"},
		{"::1", "loopback"},
		{"::1%lo", "loopback"},
		{"::ffff:127.0.0.1", "loopback"},
		{"*", "wildcard"},
		{"0.0.0.0", "wildcard"},
		{"::", "wildcard"},
		{"::ffff:0.0.0.0", "wildcard"},
		{"10.1.2.3", "lan"},
		{"172.16.0.1", "lan"},
		{"192.168.1.1", "lan"},
		{"169.254.1.1", "lan"},
		{"fd00::1", "lan"},
		{"fe80::1%eth0", "lan"},
		{"::ffff:192.168.1.1", "lan"},
		{"100.64.0.0", "tailnet"},
		{"100.127.255.255", "tailnet"},
		{"::ffff:100.64.0.1", "tailnet"},
		{"fd7a:115c:a1e0::1", "tailnet"},
		{"fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff", "tailnet"},
		{"fd7a:115c:a1df::1", "lan"},
		{"fd7a:115c:a1e1::1", "lan"},
		{"126.255.255.255", "global-address"},
		{"128.0.0.0", "global-address"},
		{"100.63.255.255", "global-address"},
		{"100.128.0.0", "global-address"},
		{"192.0.2.1", "global-address"},
		{"2001:db8::1", "global-address"},
		{"", "unknown"},
		{"localhost", "unknown"},
		{"[::1]", "unknown"},
		{"127.0.0.1:80", "unknown"},
		{"999.1.2.3", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.address, func(t *testing.T) {
			if got := exposure(tc.address); got != tc.want {
				t.Errorf("exposure(%q) = %q, want %q", tc.address, got, tc.want)
			}
		})
	}
}

func TestSocketCgroupService(t *testing.T) {
	uid := strconv.Itoa(os.Geteuid())
	otherUID := "1"
	if uid == otherUID {
		otherUID = "2"
	}
	own := "/user.slice/user-" + uid + ".slice/user@" + uid + ".service/"
	other := "/user.slice/user-" + otherUID + ".slice/user@" + otherUID + ".service/"
	cases := []struct {
		name   string
		cgroup string
		want   string
	}{
		{"empty", "", ""},
		{"no service", "/system.slice/session.scope", ""},
		{"system service", "/system.slice/example.service", "systemd:system:example.service"},
		{"nested service", "/system.slice/outer.service/inner.service/workers", "systemd:system:inner.service"},
		{"trailing slash", "/system.slice/example.service/", "systemd:system:example.service"},
		{"instance", "/system.slice/worker@blue.service", "systemd:system:worker@blue.service"},
		{"escaped unit", `/system.slice/example\x2dworker.service`, `systemd:system:example\x2dworker.service`},
		{"invalid escape", `/system.slice/example\xGG.service`, ""},
		{"invalid child falls back", "/system.slice/outer.service/bad name.service", "systemd:system:outer.service"},
		{"leading dash", "/system.slice/-bad.service", ""},
		{"empty unit name", "/system.slice/.service", ""},
		{"maximum length unit", "/system.slice/" + strings.Repeat("a", 247) + ".service", "systemd:system:" + strings.Repeat("a", 247) + ".service"},
		{"oversized unit", "/system.slice/" + strings.Repeat("a", 248) + ".service", ""},
		{"own user service", own + "app.slice/example.service", "systemd:user:example.service"},
		{"other user falls back to manager", other + "app.slice/example.service", "systemd:system:user@" + otherUID + ".service"},
		{"manager itself is system scoped", strings.TrimSuffix(own, "/"), "systemd:system:user@" + uid + ".service"},
		{"user slice alone is not user scope", "/user.slice/user-" + uid + ".slice/example.service", "systemd:system:example.service"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := socketCgroupService(tc.cgroup); got != tc.want {
				t.Errorf("socketCgroupService(%q) = %q, want %q", tc.cgroup, got, tc.want)
			}
		})
	}
}

func TestLoopbackTarget(t *testing.T) {
	cases := []struct {
		host string
		want string
		ok   bool
	}{
		{"localhost", "127.0.0.1", true},
		{"LOCALhost", "127.0.0.1", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.2.3.4", "127.2.3.4", true},
		{"127.0.0.0", "127.0.0.0", true},
		{"127.255.255.255", "127.255.255.255", true},
		{"126.255.255.255", "126.255.255.255", false},
		{"128.0.0.0", "128.0.0.0", false},
		{"::1", "::1", true},
		{"0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1", true},
		{"::ffff:127.0.0.1", "::ffff:127.0.0.1", true},
		{"::ffff:192.0.2.1", "::ffff:192.0.2.1", false},
		{"0.0.0.0", "0.0.0.0", false},
		{"::", "::", false},
		{"192.168.1.1", "192.168.1.1", false},
		{"2001:db8::1", "2001:db8::1", false},
		{"localhost.", "localhost.", false},
		{" localhost ", " localhost ", false},
		{"[::1]", "[::1]", false},
		{"::1%lo", "::1%lo", false},
		{"127.0.0.1:80", "127.0.0.1:80", false},
		{"example.invalid", "example.invalid", false},
		{"", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got, ok := loopbackTarget(tc.host)
			if got != tc.want || ok != tc.ok {
				t.Errorf("loopbackTarget(%q) = (%q, %t), want (%q, %t)", tc.host, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestSafeBackend(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   string
	}{
		{"empty", "", ""},
		{"whitespace", " \t\n", ""},
		{"bare backend", " 127.0.0.1:8080 ", "127.0.0.1:8080"},
		{"bare query", "localhost:8080/path?token=secret#part", "localhost:8080/path"},
		{"bare fragment first", "localhost:8080/path#part?token=secret", "localhost:8080/path"},
		{"url redaction", "https://user:secret@localhost:8443/path?token=secret#part", "https://localhost:8443/path"},
		{"username only", "http://user@localhost/", "http://localhost/"},
		{"ipv6 url", "http://[::1]:8080/path", "http://[::1]:8080/path"},
		{"escaped path preserved", "http://localhost/a%2Fb%3Fc%23d?secret=value", "http://localhost/a%2Fb%3Fc%23d"},
		{"control characters", " \thttp://local\x00host:8080/pa\x7fth\n ", "http://localhost:8080/path"},
		{"bare control characters", "local\x00host:8080/pa\x7fth", "localhost:8080/path"},
		{"invalid url escape", "http://localhost/%zz", "unparseable backend"},
		{"invalid ipv6 url", "http://[::1", "unparseable backend"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeBackend(tc.target); got != tc.want {
				t.Errorf("safeBackend(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}

func TestRouteID(t *testing.T) {
	// Fixed SHA-256 vectors verify stable IDs and separation of address and target.
	cases := []struct {
		name     string
		provider string
		address  string
		target   string
		want     string
	}{
		{"empty fields", "", "", "", ":6e340b9cffb37a989ca544e6"},
		{"address and target", "tailscale", "ab", "c", "tailscale:6c032e631d39a14d85aff7e3"},
		{"field boundary matters", "tailscale", "a", "bc", "tailscale:40bb547d936bbd31318ee37a"},
		{"provider namespace", "caddy", "ab", "c", "caddy:6c032e631d39a14d85aff7e3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeID(tc.provider, tc.address, tc.target); got != tc.want {
				t.Errorf("routeID(%q, %q, %q) = %q, want %q", tc.provider, tc.address, tc.target, got, tc.want)
			}
		})
	}
}
