package discovery

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/astoreyai/hostdesk/internal/model"
)

const maxUnits = 8192

func validUnit(unit string) bool {
	if len(unit) <= len(".service") || len(unit) > 255 || !strings.HasSuffix(unit, ".service") || strings.HasPrefix(unit, "-") {
		return false
	}
	for i := 0; i < len(unit); i++ {
		c := unit[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune(":_.@-", rune(c)) {
			continue
		}
		if c == '\\' && i+3 < len(unit) && unit[i+1] == 'x' {
			if _, err := strconv.ParseUint(unit[i+2:i+4], 16, 8); err == nil {
				i += 3
				continue
			}
		}
		return false
	}
	return true
}

func protectedUserUnit(unit string) bool {
	unit = strings.ToLower(unit)
	if strings.Contains(unit, "hostdesk") || strings.Contains(unit, "dbus") {
		return true
	}
	for _, prefix := range []string{"systemd-", "user@", "user-runtime-dir@", "gnome-session", "org.gnome.session", "plasma-", "xdg-desktop-portal", "xfce4-session", "mate-session", "lxqt-session", "cinnamon-session", "gnome-keyring"} {
		if strings.HasPrefix(unit, prefix) {
			return true
		}
	}
	return unit == "session-manager.service"
}

func unitProperties(data []byte) []map[string]string {
	var out []map[string]string
	current := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			if len(current) > 0 {
				out = append(out, current)
				current = map[string]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			current[key] = value
		}
	}
	if len(current) > 0 {
		out = append(out, current)
	}
	return out
}

func collectSystemd(ctx context.Context, scope string) ([]model.Service, model.Source) {
	flag := "--" + scope
	s := source("systemd:"+scope, nil)
	units := map[string]model.Service{}
	newUnit := func(name string) model.Service {
		return model.Service{ID: "systemd:" + scope + ":" + name, Name: name, Manager: "systemd", Scope: scope, State: "unknown", Ports: []int{}, Actions: []string{}}
	}
	data, filesErr := run(ctx, "systemctl", flag, "list-unit-files", "--type=service", "--no-legend", "--no-pager", "--full")
	if filesErr != nil {
		partial(&s, "installed unit inventory: "+filesErr.Error())
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !validUnit(f[0]) {
			continue
		}
		u := newUnit(f[0])
		u.Enabled = f[1]
		units[u.Name] = u
		if len(units) >= maxUnits {
			partial(&s, "unit inventory reached collection cap")
			break
		}
	}
	data, runtimeErr := run(ctx, "systemctl", flag, "list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--full", "--plain")
	if runtimeErr != nil {
		partial(&s, "runtime unit inventory: "+runtimeErr.Error())
	}
	s.Available = filesErr == nil || runtimeErr == nil
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !validUnit(f[0]) {
			continue
		}
		u, ok := units[f[0]]
		if !ok {
			u = newUnit(f[0])
		}
		u.State, u.Substate = f[2], f[3]
		units[u.Name] = u
		if len(units) >= maxUnits {
			partial(&s, "unit inventory reached collection cap")
			break
		}
	}
	names := make([]string, 0, len(units))
	for name := range units {
		names = append(names, name)
	}
	sort.Strings(names)
	detailNames := make([]string, 0, len(names))
	for _, name := range names {
		if strings.Contains(name, "@.service") {
			unit := units[name]
			unit.State = "template"
			unit.ProtectionReason = "A service template requires an instantiated unit"
			units[name] = unit
		} else {
			detailNames = append(detailNames, name)
		}
	}
	properties := "Id,Names,MainPID,LoadState,ActiveState,SubState,UnitFileState,WorkingDirectory,FragmentPath,CanStart,CanStop,RefuseManualStart,RefuseManualStop,Transient"
	for start := 0; start < len(detailNames); start += 64 {
		end := start + 64
		if end > len(detailNames) {
			end = len(detailNames)
		}
		args := []string{flag, "show", "--no-pager", "--property=" + properties, "--"}
		args = append(args, detailNames[start:end]...)
		data, err := run(ctx, "systemctl", args...)
		if err != nil {
			partial(&s, "some unit details unavailable: "+err.Error())
		}
		for _, p := range unitProperties(data) {
			id := p["Id"]
			if !validUnit(id) {
				continue
			}
			aliases := strings.Fields(p["Names"])
			aliases = append(aliases, id)
			for _, name := range aliases {
				u, exists := units[name]
				if !exists {
					continue
				}
				if p["ActiveState"] != "" {
					u.State = p["ActiveState"]
				}
				u.Substate = p["SubState"]
				if p["UnitFileState"] != "" {
					u.Enabled = p["UnitFileState"]
				}
				u.PID, _ = strconv.Atoi(p["MainPID"])
				u.WorkingDirectory, u.Path = hostDirectory(safeText(p["WorkingDirectory"])), safeText(p["FragmentPath"])
				// Transient descriptions often contain the full original command line.
				// Inventory exposes no Description/ExecStart/Environment for any unit.
				if scope == "user" {
					u.Actions = []string{}
					protected := protectedUserUnit(name) || protectedUserUnit(filepath.Base(u.Path))
					for _, alias := range aliases {
						protected = protected || protectedUserUnit(alias)
					}
					if protected {
						u.ProtectionReason = "Essential session infrastructure and Hostdesk cannot be controlled"
					}
					if !protected && p["LoadState"] == "loaded" && u.Enabled != "masked" && !strings.Contains(name, "@.service") {
						startOK := p["CanStart"] == "yes" && p["RefuseManualStart"] != "yes"
						stopOK := p["CanStop"] == "yes" && p["RefuseManualStop"] != "yes"
						if startOK && (u.State == "inactive" || u.State == "failed") {
							u.Actions = append(u.Actions, "start")
						}
						if stopOK && (u.State == "active" || u.State == "activating" || u.State == "reloading") {
							u.Actions = append(u.Actions, "stop")
						}
						if startOK && stopOK && (u.State == "active" || u.State == "reloading") {
							u.Actions = append(u.Actions, "restart")
						}
					}
				}
				units[name] = u
			}
		}
		if ctx.Err() != nil {
			partial(&s, "remaining unit details skipped after cancellation")
			break
		}
	}
	out := make([]model.Service, 0, len(names))
	for _, name := range names {
		out = append(out, units[name])
	}
	return out, s
}

// UserAction deliberately repeats discovery immediately before invoking systemctl.
// IDs never become command options or shell expressions; aliases are checked too.
func UserAction(ctx context.Context, action model.ActionRequest) error {
	if action.Operation != "start" && action.Operation != "stop" && action.Operation != "restart" {
		return errors.New("unsupported service operation")
	}
	const prefix = "systemd:user:"
	if !strings.HasPrefix(action.ID, prefix) {
		return errors.New("only current-user systemd services are controllable here")
	}
	unit := strings.TrimPrefix(action.ID, prefix)
	if !validUnit(unit) || protectedUserUnit(unit) {
		return errors.New("invalid or protected user service")
	}
	services, status := collectSystemd(ctx, "user")
	if !status.Available {
		return errors.New("user service manager unavailable")
	}
	for _, service := range services {
		if service.ID != action.ID {
			continue
		}
		for _, operation := range service.Actions {
			if operation == action.Operation {
				_, err := run(ctx, "systemctl", "--user", "--no-ask-password", action.Operation, "--", unit)
				return err
			}
		}
		return errors.New("operation is not permitted for this user service")
	}
	return errors.New("user service is not present in the current inventory")
}
