package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/astoreyai/hostdesk/internal/model"
	"gopkg.in/yaml.v3"
)

type tailscaleServe struct {
	TCP map[string]struct {
		HTTPS        bool
		HTTP         bool
		TCPForward   string
		TerminateTLS string
	}
	Web map[string]struct {
		Handlers map[string]struct {
			Proxy string
			Path  string
			Text  string
		}
	}
	AllowFunnel map[string]bool
	Foreground  map[string]*tailscaleServe
	Services    map[string]*tailscaleServe
}

func routeID(provider, address, target string) string {
	digest := sha256.Sum256([]byte(address + "\x00" + target))
	return fmt.Sprintf("%s:%x", provider, digest[:12])
}

func safeBackend(target string) string {
	target = safeText(strings.TrimSpace(target))
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil {
			return "unparseable backend"
		}
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	return target
}

func collectTailscale(ctx context.Context) ([]model.Route, model.Source) {
	out := []model.Route{}
	data, err := run(ctx, "tailscale", "serve", "status", "--json")
	s := source("tailscale-serve", err)
	if err != nil {
		return out, s
	}
	var cfg tailscaleServe
	if json.Unmarshal(data, &cfg) != nil {
		return out, source("tailscale-serve", errors.New("Serve status response could not be decoded"))
	}
	var visit func(*tailscaleServe, map[string]bool, int)
	visit = func(config *tailscaleServe, inherited map[string]bool, depth int) {
		if config == nil {
			return
		}
		if depth > 8 || len(out) >= 4096 {
			partial(&s, "Serve routes reached collection cap")
			return
		}
		funnel := map[string]bool{}
		for address, enabled := range inherited {
			funnel[address] = enabled
		}
		for address, enabled := range config.AllowFunnel {
			funnel[address] = enabled
		}
		for address, web := range config.Web {
			_, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				partial(&s, "some Serve addresses could not be decoded")
				continue
			}
			scheme := "https"
			if handler, ok := config.TCP[port]; ok && handler.HTTP && !handler.HTTPS {
				scheme = "http"
			}
			for path, handler := range web.Handlers {
				target := safeBackend(handler.Proxy)
				status, note := "not-probed", "Only loopback TCP backends are checked; route publication is not an external reachability test."
				if handler.Path != "" {
					target = "file:" + safeText(handler.Path)
					status = "local-file"
					note = "Serve file handler is configured; file contents are not inspected."
				}
				if handler.Text != "" {
					target = "text response"
					status = "text-response"
					note = "Serve text handler is configured; response contents are not exposed."
				}
				if target == "" {
					target = "unknown handler"
				}
				publicAddress := scheme + "://" + safeText(address) + safeText(path)
				out = append(out, model.Route{ID: routeID("tailscale", publicAddress, target), Provider: "tailscale", Address: publicAddress, Target: target, Status: status, Public: funnel[address], Error: note})
			}
		}
		for port, handler := range config.TCP {
			if handler.TCPForward == "" {
				continue
			}
			addresses := []string{}
			for address, enabled := range funnel {
				_, configuredPort, err := net.SplitHostPort(address)
				if enabled && err == nil && configuredPort == port {
					addresses = append(addresses, address)
				}
			}
			if len(addresses) == 0 {
				addresses = append(addresses, ":"+port)
			}
			for _, address := range addresses {
				target := safeBackend(handler.TCPForward)
				publicAddress := "tcp://" + safeText(address)
				if handler.TerminateTLS != "" {
					publicAddress = "tls://" + safeText(address)
				}
				out = append(out, model.Route{ID: routeID("tailscale", publicAddress, target), Provider: "tailscale", Address: publicAddress, Target: target, Status: "not-probed", Public: funnel[address]})
			}
		}
		for _, child := range config.Foreground {
			visit(child, funnel, depth+1)
		}
		for _, child := range config.Services {
			visit(child, funnel, depth+1)
		}
	}
	visit(&cfg, nil, 0)
	return out, s
}

type cloudflareConfig struct {
	Ingress []struct {
		Hostname string `yaml:"hostname"`
		Service  string `yaml:"service"`
	} `yaml:"ingress"`
}

func collectCloudflare(ctx context.Context, processes map[int]processInfo) ([]model.Route, model.Source) {
	routes := []model.Route{}
	s := source("cloudflare-ingress", nil)
	// Config values are read only into the selected ingress schema. Credentials,
	// tunnel identifiers, environment, and arbitrary unit arguments never escape.
	paths := map[string]bool{}
	running, unmanaged, inaccessible := 0, 0, 0
	for pid, proc := range processes {
		if ctx.Err() != nil {
			break
		}
		if proc.name != "cloudflared" {
			continue
		}
		running++
		data, err := readBounded(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"), 131072)
		if err != nil {
			inaccessible++
			continue
		}
		args := strings.Split(string(data), "\x00")
		configured := false
		for index, arg := range args {
			path := ""
			if arg == "--config" || arg == "-config" || arg == "-c" {
				if index+1 < len(args) {
					path = args[index+1]
				}
			}
			if strings.HasPrefix(arg, "--config=") {
				path = strings.TrimPrefix(arg, "--config=")
			}
			if path == "" {
				continue
			}
			if !filepath.IsAbs(path) {
				cwd, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "cwd"))
				if err != nil {
					inaccessible++
					continue
				}
				path = filepath.Join(cwd, path)
			}
			paths[filepath.Clean(path)] = true
			configured = true
		}
		if !configured {
			unmanaged++
		}
	}
	for _, path := range []string{"/etc/cloudflared/config.yml", "/etc/cloudflared/config.yaml", "/usr/local/etc/cloudflared/config.yml", "/usr/local/etc/cloudflared/config.yaml"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			paths[path] = true
		} else if os.IsPermission(err) {
			inaccessible++
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range []string{"config.yml", "config.yaml"} {
			path := filepath.Join(home, ".cloudflared", name)
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
				paths[path] = true
			} else if os.IsPermission(err) {
				inaccessible++
			}
		}
	}
	if len(paths) == 0 && running == 0 {
		if _, err := executable("cloudflared"); err != nil {
			s.Available = false
			partial(&s, "cloudflared is unavailable and no local ingress configuration was found")
		} else {
			partial(&s, "no running cloudflared process or local ingress configuration found")
		}
	}
	ordered := []string{}
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	if len(ordered) > 64 {
		ordered = ordered[:64]
		partial(&s, "Cloudflare configuration collection reached cap")
	}
	for _, path := range ordered {
		data, err := readBounded(path, 1<<20)
		if err != nil {
			inaccessible++
			continue
		}
		var cfg cloudflareConfig
		if yaml.Unmarshal(data, &cfg) != nil {
			partial(&s, "a local Cloudflare configuration could not be decoded")
			continue
		}
		if len(cfg.Ingress) > 4096 {
			cfg.Ingress = cfg.Ingress[:4096]
			partial(&s, "Cloudflare ingress reached collection cap")
		}
		for _, entry := range cfg.Ingress {
			if entry.Service == "" {
				continue
			}
			target := safeBackend(entry.Service)
			address := safeText(entry.Hostname)
			if address == "" {
				address = "catch-all"
			}
			routes = append(routes, model.Route{ID: routeID("cloudflare", address, target), Provider: "cloudflare", Address: address, Target: target, Status: "not-probed", Public: entry.Hostname != "", Error: "Configured ingress hostname, not proof of tunnel health, DNS publication or external reachability."})
		}
	}
	if inaccessible > 0 {
		partial(&s, "some running process arguments or ingress configuration files are unreadable")
	}
	if unmanaged > 0 {
		partial(&s, "some running tunnels have no explicit configuration path; remotely managed ingress is not available from local configuration")
	}
	if running == 0 && len(paths) > 0 {
		partial(&s, "local ingress configuration found without an observed running cloudflared process")
	}
	return routes, s
}

func probeRoutes(ctx context.Context, routes []model.Route) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 8)
	probes := 0
	for i := range routes {
		route := &routes[i]
		if route.Status != "not-probed" {
			continue
		}
		target := route.Target
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		parsed, err := url.Parse(target)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "https+insecure" && parsed.Scheme != "tcp" && parsed.Scheme != "tls" && parsed.Scheme != "ssh") {
			continue
		}
		host, local := loopbackTarget(parsed.Hostname())
		if !local {
			if route.Error == "" {
				route.Error = "Backend is not literal loopback; no remote connection attempted."
			}
			continue
		}
		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "http" {
				port = "80"
			} else if parsed.Scheme == "https" || parsed.Scheme == "https+insecure" {
				port = "443"
			} else {
				continue
			}
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			continue
		}
		if probes >= 128 {
			route.Error = "Local connection check cap reached."
			continue
		}
		probes++
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			route.Error = "Local connection check deadline reached."
			continue
		}
		wg.Add(1)
		go func(route *model.Route, address, alternate string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			dialer := net.Dialer{Timeout: 500 * time.Millisecond}
			connection, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil && alternate != "" {
				connection, err = dialer.DialContext(ctx, "tcp", alternate)
			}
			if err != nil {
				route.Status = "backend-unreachable"
				route.Error = "Loopback TCP connection failed; application and external route health are unknown."
				return
			}
			connection.Close()
			route.Status = "backend-reachable"
			route.Error = "Loopback TCP accepted a connection; application and external route health are not established."
		}(route, net.JoinHostPort(host, port), func() string {
			if strings.EqualFold(parsed.Hostname(), "localhost") {
				return net.JoinHostPort("::1", port)
			}
			return ""
		}())
	}
	wg.Wait()
}
