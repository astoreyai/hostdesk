package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/astoreyai/hostdesk/internal/model"
)

type processInfo struct {
	pid    int
	parent int
	name   string
	cgroup string
}

var socketPID = regexp.MustCompile(`pid=([0-9]+)`)
var socketInode = regexp.MustCompile(`\bino:([0-9]+)`)
var socketName = regexp.MustCompile(`\("([^"\n]*)"`)
var tailnetIPv4 = netip.MustParsePrefix("100.64.0.0/10")
var tailnetIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

func exposure(address string) string {
	address, _, _ = strings.Cut(address, "%")
	if address == "*" {
		return "wildcard"
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return "unknown"
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() {
		return "wildcard"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if tailnetIPv4.Contains(ip) || tailnetIPv6.Contains(ip) {
		return "tailnet"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "lan"
	}
	return "global-address"
}

func processTable(ctx context.Context) (map[int]processInfo, model.Source) {
	s := source("process-owners", nil)
	out := map[int]processInfo{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out, source("process-owners", fmt.Errorf("procfs is unreadable"))
	}
	denied := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			partial(&s, "process collection canceled")
			break
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 {
			continue
		}
		if len(out) >= 65536 {
			partial(&s, "process inventory reached collection cap")
			break
		}
		data, err := readBounded(filepath.Join("/proc", entry.Name(), "stat"), 8192)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		text := string(data)
		first, last := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
		if first < 0 || last < first {
			continue
		}
		fields := strings.Fields(text[last+1:])
		if len(fields) < 2 {
			continue
		}
		parent, _ := strconv.Atoi(fields[1])
		proc := processInfo{pid: pid, parent: parent, name: safeText(text[first+1 : last])}
		cgroup, err := readBounded(filepath.Join("/proc", entry.Name(), "cgroup"), 65536)
		if err == nil {
			proc.cgroup = string(cgroup)
		} else if os.IsPermission(err) {
			denied++
		}
		out[pid] = proc
	}
	if denied > 0 {
		partial(&s, "permissions hide some process metadata")
	}
	if os.Geteuid() != 0 {
		partial(&s, "unprivileged process and socket ownership may be incomplete")
	}
	return out, s
}

func collectListeners(ctx context.Context, processes map[int]processInfo) ([]model.Listener, []model.Source) {
	out := []model.Listener{}
	sources := []model.Source{}
	missing := map[string][]int{}
	for _, family := range []string{"4", "6"} {
		data, err := run(ctx, "ss", "-H", "-lntup", "-e", "-"+family)
		s := source("sockets:ipv"+family, err)
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			protocol := fields[0]
			if protocol != "tcp" && protocol != "udp" {
				continue
			}
			endpoint := fields[4]
			colon := strings.LastIndexByte(endpoint, ':')
			if colon < 0 {
				partial(&s, "some socket endpoints could not be decoded")
				continue
			}
			address := strings.Trim(endpoint[:colon], "[]")
			port, err := strconv.Atoi(endpoint[colon+1:])
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			listener := model.Listener{Protocol: protocol, Address: address, Port: port, Family: "ipv" + family, Exposure: exposure(address), PolicyState: "unknown", Note: "Observed host socket binding, not proof of internet reachability."}
			inode := ""
			if match := socketInode.FindStringSubmatch(line); len(match) > 1 {
				inode = match[1]
			}
			if match := socketPID.FindStringSubmatch(line); len(match) > 1 {
				listener.PID, _ = strconv.Atoi(match[1])
			}
			if match := socketName.FindStringSubmatch(line); len(match) > 1 {
				listener.Process = safeText(match[1])
			}
			for _, field := range fields[6:] {
				if cgroup, ok := strings.CutPrefix(field, "cgroup:"); ok {
					listener.ServiceID = socketCgroupService(cgroup)
				}
				if field == "v6only:0" {
					listener.Note += " Dual-stack IPv6 socket also accepts IPv4."
				}
			}
			listener.ID = fmt.Sprintf("socket:%s:%s:%s:%d:%s", listener.Family, protocol, address, port, inode)
			if listener.PID == 0 && inode != "" {
				missing[inode] = append(missing[inode], len(out))
			}
			out = append(out, listener)
			if len(out) >= 65536 {
				partial(&s, "socket inventory reached collection cap")
				break
			}
		}
		sources = append(sources, s)
	}
	if len(missing) > 0 {
		denied, scanned := false, 0
		pids := make([]int, 0, len(processes))
		for pid := range processes {
			pids = append(pids, pid)
		}
		sort.Ints(pids)
		for _, pid := range pids {
			if len(missing) == 0 || ctx.Err() != nil || scanned >= 250000 {
				break
			}
			dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
			directory, err := os.Open(dir)
			if err != nil {
				denied = denied || os.IsPermission(err)
				continue
			}
			entries, _ := directory.ReadDir(8193)
			directory.Close()
			if len(entries) > 8192 {
				entries = entries[:8192]
				denied = true
			}
			for _, entry := range entries {
				scanned++
				if scanned >= 250000 {
					break
				}
				target, err := os.Readlink(filepath.Join(dir, entry.Name()))
				if err != nil || !strings.HasPrefix(target, "socket:[") {
					continue
				}
				inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
				for _, index := range missing[inode] {
					out[index].PID = pid
					out[index].Process = processes[pid].name
				}
				delete(missing, inode)
			}
		}
		ownerSource := source("socket-owner-resolution", nil)
		if denied || len(missing) > 0 {
			partial(&ownerSource, "some socket owners are unavailable because of permissions, kernel-owned sockets or process exit")
		}
		if scanned >= 250000 {
			partial(&ownerSource, "file-descriptor collection reached cap")
		}
		sources = append(sources, ownerSource)
	}
	return out, sources
}

func processService(pid int, processes map[int]processInfo, byPID map[int]string, byUnit map[string]string, byContainer map[string]string) string {
	seen := map[int]bool{}
	for range 64 {
		if pid <= 0 || seen[pid] {
			break
		}
		seen[pid] = true
		proc, exists := processes[pid]
		if exists {
			// A child cgroup is more precise than its ancestor's MainPID. This
			// resolves worker processes and container engines' subprocesses.
			for _, line := range strings.Split(proc.cgroup, "\n") {
				parts := strings.SplitN(line, ":", 3)
				if len(parts) != 3 {
					continue
				}
				segments := strings.Split(parts[2], "/")
				for i := len(segments) - 1; i >= 0; i-- {
					segment := segments[i]
					container := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(segment, "docker-"), "libpod-"), ".scope")
					if id := byContainer[container]; id != "" {
						return id
					}
					scope := "system"
					for _, ancestor := range segments[:i] {
						if strings.HasPrefix(ancestor, "user@") && strings.HasSuffix(ancestor, ".service") {
							scope = "user"
							break
						}
					}
					if id := byUnit[scope+":"+segment]; id != "" {
						if scope != "user" || sameUserProcess(pid) {
							return id
						}
					}
				}
			}
		}
		if id := byPID[pid]; id != "" {
			return id
		}
		if !exists {
			break
		}
		pid = proc.parent
	}
	return ""
}

func socketCgroupService(cgroup string) string {
	segments := strings.Split(cgroup, "/")
	ownUser := strings.Contains(cgroup, "/user-"+strconv.Itoa(os.Geteuid())+".slice/")
	for i := len(segments) - 1; i >= 0; i-- {
		if !validUnit(segments[i]) {
			continue
		}
		scope := "system"
		for _, ancestor := range segments[:i] {
			if strings.HasPrefix(ancestor, "user@") && strings.HasSuffix(ancestor, ".service") {
				scope = "user"
				break
			}
		}
		if scope == "user" && !ownUser {
			continue
		}
		return "systemd:" + scope + ":" + segments[i]
	}
	return ""
}

func sameUserProcess(pid int) bool {
	// A broker snapshot may contain other users' listeners. Do not attach them
	// to a same-named service belonging to the dashboard user.
	info, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	return err == nil && fileOwnedByCurrentUser(info)
}

func correlate(services []model.Service, listeners []model.Listener, processes map[int]processInfo) {
	byPID, byUnit, byContainer := map[int]string{}, map[string]string{}, map[string]string{}
	index := map[string]int{}
	for i := range services {
		s := &services[i]
		index[s.ID] = i
		if s.PID > 0 {
			byPID[s.PID] = s.ID
		}
		if s.Manager == "systemd" {
			byUnit[s.Scope+":"+s.Name] = s.ID
		} else {
			parts := strings.Split(s.ID, ":")
			if len(parts) == 3 {
				byContainer[parts[2]] = s.ID
			}
		}
	}
	for i := range listeners {
		l := &listeners[i]
		if l.PID > 0 {
			if proc, ok := processes[l.PID]; ok && l.Process == "" {
				l.Process = proc.name
			}
			if !strings.Contains(l.ServiceID, ":container:") {
				if id := processService(l.PID, processes, byPID, byUnit, byContainer); id != "" {
					l.ServiceID = id
				}
			}
		}
		if si, ok := index[l.ServiceID]; ok {
			services[si].Ports = appendUniqueInt(services[si].Ports, l.Port)
		}
	}
	for i := range services {
		sort.Ints(services[i].Ports)
	}
}

func loopbackTarget(host string) (string, bool) {
	if strings.EqualFold(host, "localhost") {
		return "127.0.0.1", true
	}
	ip := net.ParseIP(host)
	return host, ip != nil && ip.IsLoopback()
}
