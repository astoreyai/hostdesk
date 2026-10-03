package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/astoreyai/hostdesk/internal/model"
)

type containerBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type containerDetails struct {
	ID     string                        `json:"id"`
	Name   string                        `json:"name"`
	Status string                        `json:"status"`
	PID    int                           `json:"pid"`
	Ports  map[string][]containerBinding `json:"ports"`
}

func validContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Inspect projects only explicitly selected fields. Full inspect output includes
// environment variables, registry credentials and secret mount locations.
func collectContainers(ctx context.Context, engine, scope, endpoint string) ([]model.Service, []model.Listener, model.Source) {
	prefix := []string{}
	if engine == "docker" {
		if endpoint == "" {
			endpoint = "unix:///var/run/docker.sock"
		}
		prefix = append(prefix, "--host", endpoint)
	} else if engine == "podman" {
		endpoint = "unix:///run/podman/podman.sock"
		if scope == "user" {
			runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
			if !filepath.IsAbs(runtimeDir) {
				return []model.Service{}, []model.Listener{}, source(engine+":"+scope, fmt.Errorf("rootless Podman API requires an absolute XDG_RUNTIME_DIR and its podman.socket service"))
			}
			endpoint = "unix://" + filepath.Join(runtimeDir, "podman", "podman.sock")
		}
		prefix = append(prefix, "--remote=true", "--url", endpoint)
	}
	args := append(append([]string{}, prefix...), "ps", "--all", "--quiet", "--no-trunc")
	data, err := run(ctx, engine, args...)
	s := source(engine+":"+scope, err)
	if err != nil && engine == "podman" {
		s.Error += "; local Podman API socket must be available (podman.socket)"
	}
	services, listeners := []model.Service{}, []model.Listener{}
	if err != nil {
		return services, listeners, s
	}
	ids := strings.Fields(string(data))
	if len(ids) > 4096 {
		ids = ids[:4096]
		partial(&s, "container inventory reached collection cap")
	}
	format := `{"id":{{json .Id}},"name":{{json .Name}},"status":{{json .State.Status}},"pid":{{json .State.Pid}},"ports":{{json .NetworkSettings.Ports}}}`
	for start := 0; start < len(ids); start += 32 {
		end := start + 32
		if end > len(ids) {
			end = len(ids)
		}
		batch := []string{}
		for _, id := range ids[start:end] {
			if validContainerID(id) {
				batch = append(batch, id)
			} else {
				partial(&s, "engine returned a noncanonical container ID")
			}
		}
		if len(batch) == 0 {
			continue
		}
		args = append(append([]string{}, prefix...), "inspect", "--format", format)
		args = append(args, batch...)
		data, inspectErr := run(ctx, engine, args...)
		if inspectErr != nil {
			partial(&s, "container details incomplete: "+inspectErr.Error())
		}
		found := map[string]bool{}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var item containerDetails
			if json.Unmarshal([]byte(line), &item) != nil || !validContainerID(item.ID) {
				partial(&s, "container detail response could not be decoded")
				continue
			}
			found[item.ID] = true
			service := model.Service{ID: engine + ":container:" + item.ID, Name: strings.TrimPrefix(safeText(item.Name), "/"), Manager: engine, Scope: scope, State: item.Status, PID: item.PID, Ports: []int{}, Actions: []string{}}
			// Container WorkingDir is inside its mount namespace, not a host project.
			if service.Name == "" {
				service.Name = item.ID[:12]
			}
			for key, bindings := range item.Ports {
				_, protocol, ok := strings.Cut(key, "/")
				if !ok || (protocol != "tcp" && protocol != "udp") {
					continue
				}
				for _, binding := range bindings {
					port, err := strconv.Atoi(binding.HostPort)
					if err != nil || port < 1 || port > 65535 {
						continue
					}
					service.Ports = appendUniqueInt(service.Ports, port)
					if item.Status != "running" {
						continue
					}
					address := binding.HostIP
					if address == "" {
						address = "0.0.0.0"
					}
					family := "ipv4"
					if strings.Contains(address, ":") {
						family = "ipv6"
					}
					listeners = append(listeners, model.Listener{ID: fmt.Sprintf("%s:publish:%s:%s:%s:%d", engine, item.ID, protocol, address, port), Protocol: protocol, Address: address, Port: port, Family: family, Exposure: exposure(address), ServiceID: service.ID, PolicyState: "unknown", Note: "Engine-reported published mapping; may use NAT without a host socket. Host INPUT rules may not govern forwarded container traffic; internet reachability is not established."})
				}
			}
			sort.Ints(service.Ports)
			services = append(services, service)
		}
		for _, id := range batch {
			if !found[id] {
				services = append(services, model.Service{ID: engine + ":container:" + id, Name: id[:12], Manager: engine, Scope: scope, State: "unknown", Ports: []int{}, Actions: []string{}})
			}
		}
		if ctx.Err() != nil {
			partial(&s, "remaining containers skipped after cancellation")
			break
		}
	}
	return services, listeners, s
}

func appendUniqueInt(values []int, value int) []int {
	for _, existing := range values {
		if value == existing {
			return values
		}
	}
	return append(values, value)
}
