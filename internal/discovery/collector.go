package discovery

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/astoreyai/hostdesk/internal/model"
)

type Collector struct {
	ProjectRoots []string
	Privileged   func(context.Context) (model.PrivilegedSnapshot, error)
}

func fileOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func emptyPrivileged() model.PrivilegedSnapshot {
	return model.PrivilegedSnapshot{Sources: []model.Source{}, Services: []model.Service{}, Listeners: []model.Listener{}, Routes: []model.Route{}, Warnings: []string{}}
}

func hostInfo() model.Host {
	host := model.Host{OS: "Linux", Architecture: runtime.GOARCH}
	host.Name, _ = os.Hostname()
	if data, err := readBounded("/proc/sys/kernel/osrelease", 4096); err == nil {
		host.Kernel = strings.TrimSpace(string(data))
	}
	if data, err := readBounded("/etc/os-release", 65536); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if value, found := strings.CutPrefix(line, "PRETTY_NAME="); found {
				if unquoted, err := strconv.Unquote(value); err == nil {
					value = unquoted
				} else {
					value = strings.Trim(value, "'\"")
				}
				host.OS = safeText(value)
				break
			}
		}
	}
	return host
}

// CollectPrivileged can run without root, but never presents denied sources as an
// empty successful inventory. Broker policy, not discovery, grants root actions.
func CollectPrivileged(ctx context.Context) model.PrivilegedSnapshot {
	snapshot, _ := collectPrivileged(ctx)
	return snapshot
}

func collectPrivileged(ctx context.Context) (model.PrivilegedSnapshot, map[int]processInfo) {
	ctx, cancel := context.WithTimeout(ctx, 24*time.Second)
	defer cancel()
	parts := make([]model.PrivilegedSnapshot, 5)
	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		services, status := collectSystemd(ctx, "system")
		parts[0] = model.PrivilegedSnapshot{Services: services, Sources: []model.Source{status}}
	}()
	for index, engine := range []string{"docker", "podman"} {
		go func(index int, engine string) {
			defer wg.Done()
			scope := "system"
			if os.Geteuid() != 0 && engine == "podman" {
				scope = "user"
			}
			services, listeners, status := collectContainers(ctx, engine, scope, "")
			parts[index+1] = model.PrivilegedSnapshot{Services: services, Listeners: listeners, Sources: []model.Source{status}}
		}(index, engine)
	}
	go func() {
		defer wg.Done()
		routes, status := collectTailscale(ctx)
		parts[3] = model.PrivilegedSnapshot{Routes: routes, Sources: []model.Source{status}}
	}()
	go func() {
		defer wg.Done()
		sources, warnings := collectFirewall(ctx)
		parts[4] = model.PrivilegedSnapshot{Sources: sources, Warnings: warnings}
	}()
	processes, processSource := processTable(ctx)
	listeners, listenerSources := collectListeners(ctx, processes)
	routes, cloudflareSource := collectCloudflare(ctx, processes)
	wg.Wait()
	snapshot := emptyPrivileged()
	snapshot.Sources = append(snapshot.Sources, processSource, cloudflareSource)
	snapshot.Sources = append(snapshot.Sources, listenerSources...)
	snapshot.Listeners, snapshot.Routes = listeners, routes
	for _, part := range parts {
		snapshot.Services = append(snapshot.Services, part.Services...)
		snapshot.Listeners = mergeListeners(snapshot.Listeners, part.Listeners)
		snapshot.Routes = append(snapshot.Routes, part.Routes...)
		snapshot.Sources = append(snapshot.Sources, part.Sources...)
		snapshot.Warnings = append(snapshot.Warnings, part.Warnings...)
	}
	correlate(snapshot.Services, snapshot.Listeners, processes)
	snapshot.Routes = uniqueRoutes(snapshot.Routes)
	probeRoutes(ctx, snapshot.Routes)
	if os.Geteuid() != 0 {
		snapshot.Warnings = append(snapshot.Warnings, "Discovery is running without root. System unit names may be available while socket ownership, containers, tunnel configuration and effective firewall evidence remain partial.")
	}
	snapshot.Warnings = append(snapshot.Warnings, "Bindings and configured published routes are not proof of internet reachability. Host INPUT rules may not control NAT-forwarded container traffic.")
	for _, listener := range snapshot.Listeners {
		if strings.Contains(listener.ServiceID, ":container:") && listener.Exposure != "loopback" && strings.Contains(listener.Note, "published") {
			snapshot.Warnings = append(snapshot.Warnings, "A container engine reports nonloopback published ports. Bridge/NAT publications traverse FORWARD rather than host INPUT; Hostdesk's input guard does not protect those forwarded ports. Host-network container sockets do traverse INPUT.")
			break
		}
	}
	sortPrivileged(&snapshot)
	return snapshot, processes
}

func (c *Collector) Collect(ctx context.Context) model.Snapshot {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	var userServices []model.Service
	var userSource model.Source
	var userWG sync.WaitGroup
	userWG.Add(1)
	go func() { defer userWG.Done(); userServices, userSource = collectSystemd(ctx, "user") }()
	var privileged model.PrivilegedSnapshot
	var processes map[int]processInfo
	brokerSource := model.Source{Name: "broker", CheckedAt: time.Now().UTC()}
	brokerOK := false
	if c.Privileged != nil {
		brokerCtx, brokerCancel := context.WithTimeout(ctx, 26*time.Second)
		result, err := c.Privileged(brokerCtx)
		brokerCancel()
		if err == nil {
			privileged = result
			brokerOK = true
			brokerSource.Available = true
		} else {
			brokerSource.Error = "Privileged broker unavailable; using actual unprivileged discovery. System and network controls are unavailable."
		}
	} else {
		brokerSource.Error = "Privileged broker is not configured; using actual unprivileged discovery."
	}
	if !brokerOK {
		privileged, processes = collectPrivileged(ctx)
	}
	if brokerOK {
		var processSource model.Source
		processes, processSource = processTable(ctx)
		processSource.Name = "current-user-processes"
		privileged.Sources = append(privileged.Sources, processSource)
		if os.Geteuid() != 0 {
			services, listeners, status := collectContainers(ctx, "podman", "user", "")
			privileged.Services = append(privileged.Services, services...)
			privileged.Listeners = mergeListeners(privileged.Listeners, listeners)
			privileged.Sources = append(privileged.Sources, status)
		}
	}
	if os.Geteuid() != 0 {
		// A rootless Docker socket is distinct from the broker's system engine.
		// An explicit local endpoint prevents Docker contexts from selecting a remote host.
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(runtimeDir) {
			socket := filepath.Join(runtimeDir, "docker.sock")
			if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 && fileOwnedByCurrentUser(info) {
				services, listeners, status := collectContainers(ctx, "docker", "user", "unix://"+socket)
				privileged.Services = append(privileged.Services, services...)
				privileged.Listeners = mergeListeners(privileged.Listeners, listeners)
				privileged.Sources = append(privileged.Sources, status)
			}
		}
	}
	userWG.Wait()
	privileged.Services = append(privileged.Services, userServices...)
	privileged.Sources = append(privileged.Sources, brokerSource, userSource)
	correlate(privileged.Services, privileged.Listeners, processes)
	projects, projectSource := collectProjects(ctx, c.ProjectRoots, privileged.Services)
	privileged.Sources = append(privileged.Sources, projectSource)
	if !brokerOK {
		privileged.Warnings = append(privileged.Warnings, brokerSource.Error)
	}
	if ctx.Err() != nil {
		privileged.Warnings = append(privileged.Warnings, "Collection deadline or cancellation interrupted this snapshot; inspect individual source diagnostics.")
	}
	sortPrivileged(&privileged)
	return model.Snapshot{Version: 1, GeneratedAt: time.Now().UTC(), Host: hostInfo(), Sources: privileged.Sources, Services: privileged.Services, Listeners: privileged.Listeners, Projects: projects, Routes: privileged.Routes, Warnings: privileged.Warnings}
}

func mergeListeners(listeners, mappings []model.Listener) []model.Listener {
	for _, mapping := range mappings {
		matched := false
		for i := range listeners {
			listener := &listeners[i]
			if listener.Protocol == mapping.Protocol && listener.Port == mapping.Port && listener.Family == mapping.Family && (listener.Address == mapping.Address || (listener.Address == "*" && exposure(mapping.Address) == "wildcard")) {
				listener.ServiceID = mapping.ServiceID
				listener.Note += " Also published by a container engine; NAT forwarding may bypass host INPUT policy."
				matched = true
			}
		}
		if !matched {
			listeners = append(listeners, mapping)
		}
	}
	return listeners
}

func uniqueRoutes(routes []model.Route) []model.Route {
	seen := map[string]bool{}
	out := make([]model.Route, 0, len(routes))
	for _, route := range routes {
		if !seen[route.ID] {
			seen[route.ID] = true
			out = append(out, route)
		}
	}
	return out
}

func sortPrivileged(snapshot *model.PrivilegedSnapshot) {
	sort.Slice(snapshot.Services, func(i, j int) bool { return snapshot.Services[i].ID < snapshot.Services[j].ID })
	sort.Slice(snapshot.Listeners, func(i, j int) bool { return snapshot.Listeners[i].ID < snapshot.Listeners[j].ID })
	sort.Slice(snapshot.Routes, func(i, j int) bool { return snapshot.Routes[i].ID < snapshot.Routes[j].ID })
	sort.Slice(snapshot.Sources, func(i, j int) bool { return snapshot.Sources[i].Name < snapshot.Sources[j].Name })
}
