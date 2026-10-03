package broker

import (
	"context"
	"regexp"
	"strings"

	"github.com/astoreyai/hostdesk/internal/discovery"
	"github.com/astoreyai/hostdesk/internal/model"
)

var unitPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@:\\-]*\.service$`)
var containerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var fullIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validUnit(unit string) bool { return len(unit) <= 255 && unitPattern.MatchString(unit) }
func validContainerName(name string) bool {
	return len(name) <= 256 && containerPattern.MatchString(name)
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (b *service) permitted(s model.Service) bool {
	if strings.HasPrefix(s.ID, "systemd:system:") {
		unit := strings.TrimPrefix(s.ID, "systemd:system:")
		return validUnit(unit) && contains(b.policy.AllowedSystemUnits, unit)
	}
	parts := strings.SplitN(s.ID, ":", 3)
	if len(parts) != 3 || parts[1] != "container" || (parts[0] != "docker" && parts[0] != "podman") || !fullIDPattern.MatchString(parts[2]) {
		return false
	}
	return contains(b.policy.AllowedContainers, parts[2]) || contains(b.policy.AllowedContainers, strings.TrimPrefix(s.Name, "/"))
}

func (b *service) snapshot(ctx context.Context) model.PrivilegedSnapshot {
	b.inventoryMu.Lock()
	defer b.inventoryMu.Unlock()
	snapshot := discovery.CollectPrivileged(ctx)
	for i := range snapshot.Services {
		s := &snapshot.Services[i]
		s.Actions = []string{}
		if b.permitted(*s) {
			s.Actions = []string{"start", "stop", "restart"}
			s.ProtectionReason = ""
		} else {
			s.ProtectionReason = "Not explicitly authorized by the root-owned broker policy"
		}
	}
	b.annotateNetwork(ctx, &snapshot)
	return snapshot
}

func (b *service) action(ctx context.Context, req model.ActionRequest, actor string) error {
	if err := validateActor(actor); err != nil {
		return err
	}
	if req.Operation != "start" && req.Operation != "stop" && req.Operation != "restart" {
		return invalid("unsupported lifecycle operation")
	}
	parts := strings.SplitN(req.ID, ":", 3)
	if len(parts) != 3 {
		return invalid("invalid service identifier")
	}
	b.actionMu.Lock()
	defer b.actionMu.Unlock()
	var executable string
	var args []string
	if parts[0] == "systemd" && parts[1] == "system" {
		unit := parts[2]
		if !validUnit(unit) {
			return invalid("invalid system service identifier")
		}
		if !contains(b.policy.AllowedSystemUnits, unit) {
			return forbidden("system service is not explicitly allowlisted")
		}
		data, err := run(ctx, "systemctl", "", "--system", "--no-pager", "--no-ask-password", "show", "--property=Id,LoadState", "--", unit)
		if err != nil {
			return err
		}
		properties := make(map[string]string)
		for _, line := range strings.Split(string(data), "\n") {
			if key, value, ok := strings.Cut(line, "="); ok {
				properties[key] = value
			}
		}
		if properties["Id"] != unit || properties["LoadState"] != "loaded" {
			return stale("system service is not an exact loaded service")
		}
		executable = "systemctl"
		args = []string{"--system", "--no-pager", "--no-ask-password", req.Operation, "--", unit}
	} else if (parts[0] == "docker" || parts[0] == "podman") && parts[1] == "container" {
		id := parts[2]
		if !fullIDPattern.MatchString(id) {
			return invalid("container operation requires the full immutable identifier")
		}
		prefix := []string{"--host", "unix:///var/run/docker.sock"}
		if parts[0] == "podman" {
			prefix = []string{"--remote=true", "--url", "unix:///run/podman/podman.sock"}
		}
		inspectArgs := append(append([]string{}, prefix...), "container", "inspect", "--format", "{{.Id}}|{{.Name}}", "--", id)
		data, err := run(ctx, parts[0], "", inspectArgs...)
		if err != nil {
			return err
		}
		actualID, name, ok := strings.Cut(strings.TrimSpace(string(data)), "|")
		name = strings.TrimPrefix(name, "/")
		if !ok || actualID != id || !validContainerName(name) {
			return stale("container identity changed or cannot be validated")
		}
		if !contains(b.policy.AllowedContainers, id) && !contains(b.policy.AllowedContainers, name) {
			return forbidden("container is not explicitly allowlisted")
		}
		executable = parts[0]
		args = append(prefix, "container", req.Operation, "--", id)
	} else {
		return forbidden("broker does not control this service scope")
	}
	if err := b.audit(actor, req.Operation, req.ID, false, "authorized operation requested"); err != nil {
		return err
	}
	_, err := run(ctx, executable, "", args...)
	detail := "operation completed"
	if err != nil {
		detail = "operation failed; state may have changed, refresh inventory"
	}
	if auditErr := b.audit(actor, req.Operation, req.ID, err == nil, detail); auditErr != nil {
		return auditErr
	}
	return err
}
