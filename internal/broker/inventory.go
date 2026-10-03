package broker

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/astoreyai/hostdesk/internal/model"
)

func hasPort(ports []int, port int) bool {
	index := sort.SearchInts(ports, port)
	return index < len(ports) && ports[index] == port
}

func (b *service) annotateNetwork(ctx context.Context, snapshot *model.PrivilegedSnapshot) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.state.Applied && b.state.Pending == nil {
		return
	}
	current, err := inspectTable(ctx)
	if err != nil {
		snapshot.Warnings = append(snapshot.Warnings, "Hostdesk firewall evidence is unavailable; listener policy annotations remain unknown.")
		return
	}
	if b.installedFingerprint == "" || b.installedFingerprint != current.fingerprint {
		snapshot.Warnings = append(snapshot.Warnings, "The Hostdesk table differs from the broker's last installed policy; listener filtering cannot be asserted.")
		return
	}
	policy, peers, protected := b.state.Policy, b.state.PeerPorts, b.state.ManagementPorts
	if pending := b.state.Pending; pending != nil {
		policy, peers, protected = pending.Policy, pending.PeerPorts, pending.ManagementPorts
	}
	if len(policy.Interfaces) == 0 {
		return
	}
	snapshot.Warnings = append(snapshot.Warnings, "Hostdesk guards only NEW host INPUT TCP/UDP on selected interfaces. Existing host firewalls still apply; unmanaged interfaces and Docker bridge FORWARD traffic are not covered.")
	managed := make(map[string]model.InterfacePolicy, len(policy.Interfaces))
	for _, iface := range policy.Interfaces {
		managed[iface.Name] = iface
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	addressInterface := make(map[string]string)
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			key := ip.String()
			if previous, exists := addressInterface[key]; exists && previous != iface.Name {
				addressInterface[key] = ""
			} else {
				addressInterface[key] = iface.Name
			}
		}
	}
	for i := range snapshot.Listeners {
		listener := &snapshot.Listeners[i]
		protocol := strings.TrimSuffix(strings.ToLower(listener.Protocol), "6")
		if protocol != "tcp" && protocol != "udp" {
			continue
		}
		// Published bridge-container records are not host INPUT listeners. The
		// discovery note identifies this boundary; never classify their forwarding.
		if strings.Contains(strings.ToLower(listener.Note), "forward") || strings.Contains(strings.ToLower(listener.Process), "docker-proxy") {
			listener.Note = joinNote(listener.Note, "Docker forwarding is outside the Hostdesk INPUT guard.")
			continue
		}
		address := strings.Trim(listener.Address, "[]")
		address, _, _ = strings.Cut(address, "%")
		ip := net.ParseIP(address)
		if address == "*" || (ip != nil && ip.IsUnspecified()) {
			listener.PolicyState = "mixed"
			listener.Note = joinNote(listener.Note, "Wildcard binding spans interfaces: Hostdesk filtering is interface-specific, not a global allow/block verdict.")
			continue
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		iface, exists := managed[addressInterface[ip.String()]]
		if !exists {
			continue
		}
		allowed := hasPort(iface.UDPPorts, listener.Port)
		if protocol == "tcp" {
			allowed = hasPort(iface.TCPPorts, listener.Port) || hasPort(protected, listener.Port) || (iface.AllowTailscalePeerAPI && hasPort(peers, listener.Port))
		}
		if allowed {
			listener.PolicyState = "allowed-by-hostdesk"
			listener.Note = joinNote(listener.Note, "Hostdesk permits this interface/port; later firewall rules and published routes still determine access.")
		} else {
			listener.PolicyState = "blocked-new-by-hostdesk"
			listener.Note = joinNote(listener.Note, "Hostdesk drops NEW inbound connections on this interface/port; established connections are unaffected.")
		}
	}
}

func joinNote(existing, additional string) string {
	if existing == "" {
		return additional
	}
	return existing + " " + additional
}
