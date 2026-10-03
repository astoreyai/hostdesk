package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/astoreyai/hostdesk/internal/model"
)

const tableName = "hostdesk_guard"

var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var sshProcessPattern = regexp.MustCompile(`\("(?:sshd(?:-session)?|dropbear)",pid=([0-9]+),`)

type tableState struct {
	text        string
	fingerprint string
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func inspectTable(ctx context.Context) (tableState, error) {
	data, err := run(ctx, "nft", "", "--json", "list", "tables")
	if err != nil {
		return tableState{}, err
	}
	var listing struct {
		NFTables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		return tableState{}, unavailable("nftables returned an unreadable table listing")
	}
	for _, item := range listing.NFTables {
		if item.Table != nil && item.Table.Family == "inet" && item.Table.Name == tableName {
			text, err := run(ctx, "nft", "", "--stateless", "list", "table", "inet", tableName)
			if err != nil {
				return tableState{}, err
			}
			return tableState{text: string(text), fingerprint: fingerprint(string(text))}, nil
		}
	}
	return tableState{fingerprint: fingerprint("")}, nil
}

func normalizePorts(ports []int) ([]int, error) {
	set := make(map[int]bool, len(ports))
	result := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, invalid("ports must be between 1 and 65535")
		}
		if !set[port] {
			set[port] = true
			result = append(result, port)
		}
	}
	sort.Ints(result)
	return result, nil
}

func validatePolicy(policy model.NetworkPolicy, protected []int) (model.NetworkPolicy, error) {
	if policy.Interfaces == nil {
		return policy, invalid("policy.interfaces must be an explicit array; use [] only to remove the guard intentionally")
	}
	return normalizePolicy(policy, protected, true)
}

func normalizePolicy(policy model.NetworkPolicy, protected []int, requirePresent bool) (model.NetworkPolicy, error) {
	interfaces, err := net.Interfaces()
	if requirePresent && err != nil {
		return policy, unavailable("network interface inventory is unavailable")
	}
	existing := make(map[string]bool, len(interfaces))
	for _, iface := range interfaces {
		existing[iface.Name] = true
	}
	seen := make(map[string]bool)
	result := model.NetworkPolicy{Interfaces: make([]model.InterfacePolicy, 0, len(policy.Interfaces))}
	for _, iface := range policy.Interfaces {
		if !interfacePattern.MatchString(iface.Name) || (requirePresent && !existing[iface.Name]) {
			return result, invalid("policy contains an invalid or nonexistent network interface")
		}
		if seen[iface.Name] {
			return result, invalid("policy contains duplicate network interfaces")
		}
		seen[iface.Name] = true
		iface.TCPPorts, err = normalizePorts(iface.TCPPorts)
		if err != nil {
			return result, err
		}
		iface.UDPPorts, err = normalizePorts(iface.UDPPorts)
		if err != nil {
			return result, err
		}
		for _, port := range protected {
			index := sort.SearchInts(iface.TCPPorts, port)
			if index == len(iface.TCPPorts) || iface.TCPPorts[index] != port {
				return result, invalid("every managed interface must explicitly preserve all protected management TCP ports")
			}
		}
		result.Interfaces = append(result.Interfaces, iface)
	}
	sort.Slice(result.Interfaces, func(i, j int) bool { return result.Interfaces[i].Name < result.Interfaces[j].Name })
	return result, nil
}

func listenerPort(address string) int {
	index := strings.LastIndexByte(address, ':')
	if index < 0 {
		return 0
	}
	port, err := strconv.Atoi(address[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func trustedSSHProcess(pid string) bool {
	proc := filepath.Join("/proc", pid)
	status, err := os.ReadFile(filepath.Join(proc, "status"))
	if err != nil {
		return false
	}
	rootUIDs := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "Uid:" {
			rootUIDs = fields[1] == "0" && fields[2] == "0" && fields[3] == "0" && fields[4] == "0"
			break
		}
	}
	if !rootUIDs {
		return false
	}
	link := filepath.Join(proc, "exe")
	executable, err := os.Readlink(link)
	if err != nil {
		return false
	}
	executable = strings.TrimSuffix(executable, " (deleted)")
	switch filepath.Base(executable) {
	case "sshd", "sshd-session", "dropbear":
	default:
		return false
	}
	// The executable can be replaced during an upgrade while the old daemon
	// still listens. Validate its live inode and trusted parent, not just comm.
	info, err := os.Stat(link)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && rootPath(filepath.Dir(executable), true, false) == nil
}

func (b *service) protectedPorts(ctx context.Context) ([]int, error) {
	ports := append([]int(nil), b.policy.ProtectedTCPPorts...)
	// ss is read under root so actual SSH owners are visible even when inventory
	// source collection is otherwise partial. No configured SSH default is guessed.
	data, err := run(ctx, "ss", "", "-H", "-lntp")
	if err != nil {
		return nil, unavailable("live SSH listener protection requires readable socket ownership")
	}
	for _, line := range strings.Split(string(data), "\n") {
		trusted := false
		for _, match := range sshProcessPattern.FindAllStringSubmatch(line, -1) {
			if trustedSSHProcess(match[1]) {
				trusted = true
				break
			}
		}
		if !trusted {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			if port := listenerPort(fields[3]); port != 0 {
				ports = append(ports, port)
			}
		}
	}
	// Socket-activated SSH listeners belong to systemd rather than sshd.
	if _, err := safeExecutable("systemctl"); err == nil {
		if data, err := run(ctx, "systemctl", "", "--system", "--no-pager", "show", "--property=Listen", "--value", "--", "ssh.socket", "sshd.socket", "dropbear.socket"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] == "(Stream)" {
					port := listenerPort(fields[0])
					if port == 0 {
						port, _ = strconv.Atoi(fields[0])
					}
					if port > 0 && port <= 65535 {
						ports = append(ports, port)
					}
				}
			}
		}
	}
	return normalizePorts(ports)
}

func peerAPIPorts(ctx context.Context, policy model.NetworkPolicy) ([]int, error) {
	needed := false
	for _, iface := range policy.Interfaces {
		needed = needed || iface.AllowTailscalePeerAPI
	}
	if !needed {
		return []int{}, nil
	}
	data, err := run(ctx, "tailscale", "", "status", "--json")
	if err != nil {
		return nil, unavailable("Tailscale peer API ports cannot be discovered")
	}
	var status struct {
		BackendState string `json:"BackendState"`
		Self         *struct {
			PeerAPIURL []string `json:"PeerAPIURL"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(data, &status); err != nil || status.Self == nil || status.BackendState != "Running" {
		return nil, unavailable("Tailscale is not running or its peer API state is unreadable")
	}
	ports := make([]int, 0, len(status.Self.PeerAPIURL))
	for _, raw := range status.Self.PeerAPIURL {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || net.ParseIP(u.Hostname()) == nil {
			return nil, unavailable("Tailscale returned an invalid peer API endpoint")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, unavailable("Tailscale returned an invalid peer API port")
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, unavailable("Tailscale has no current peer API listeners")
	}
	return normalizePorts(ports)
}

func portSet(ports []int) string {
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(port)
	}
	return "{ " + strings.Join(values, ", ") + " }"
}

func renderTable(policy model.NetworkPolicy, peerPorts []int) string {
	if len(policy.Interfaces) == 0 {
		return ""
	}
	var rules strings.Builder
	rules.WriteString("table inet hostdesk_guard {\n chain input {\n  type filter hook input priority -20; policy accept;\n  ct state established,related accept\n  iifname \"lo\" accept\n  meta l4proto { icmp, ipv6-icmp } accept\n")
	for _, iface := range policy.Interfaces {
		tcp := append([]int(nil), iface.TCPPorts...)
		if iface.AllowTailscalePeerAPI {
			tcp = append(tcp, peerPorts...)
			tcp, _ = normalizePorts(tcp)
		}
		name := strconv.Quote(iface.Name)
		if len(tcp) != 0 {
			fmt.Fprintf(&rules, "  iifname %s tcp dport %s accept\n", name, portSet(tcp))
		}
		if len(iface.UDPPorts) != 0 {
			fmt.Fprintf(&rules, "  iifname %s udp dport %s accept\n", name, portSet(iface.UDPPorts))
		}
		fmt.Fprintf(&rules, "  iifname %s meta l4proto { tcp, udp } ct state new drop\n", name)
	}
	rules.WriteString(" }\n}\n")
	return rules.String()
}

func transaction(current tableState, desired string) string {
	var script strings.Builder
	if current.text != "" {
		script.WriteString("delete table inet hostdesk_guard\n")
	}
	script.WriteString(desired)
	return script.String()
}

func checkTransaction(ctx context.Context, script string) error {
	// Even an empty policy needs a real nft capability check, never a fake success.
	_, err := run(ctx, "nft", script, "--check", "--file", "-")
	if err != nil {
		return invalid("nftables could not validate this policy; no changes were made")
	}
	return nil
}

func applyTransaction(ctx context.Context, current tableState, desired string) error {
	script := transaction(current, desired)
	if script == "" {
		_, err := inspectTable(ctx)
		return err
	}
	_, err := run(ctx, "nft", script, "--file", "-")
	return err
}
