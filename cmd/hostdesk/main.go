//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/astoreyai/hostdesk/internal/broker"
	"github.com/astoreyai/hostdesk/internal/config"
	"github.com/astoreyai/hostdesk/internal/discovery"
	"github.com/astoreyai/hostdesk/internal/model"
	"github.com/astoreyai/hostdesk/internal/webserver"
)

var version = "dev"

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "hostdesk:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	if args[0] == "version" {
		fmt.Println("hostdesk", version)
		return nil
	}
	if args[0] == "help" || args[0] == "--help" {
		usage()
		return nil
	}
	if args[0] == "install-broker" {
		return installBroker(ctx, args[1:])
	}
	if args[0] == "broker" {
		f := flag.NewFlagSet("broker", flag.ContinueOnError)
		path := f.String("policy", "/etc/hostdesk/broker.json", "root-owned policy path")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected broker arguments")
		}
		return broker.Serve(ctx, *path)
	}
	defaultPath, err := config.DefaultPath()
	if err != nil {
		return err
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := f.String("config", defaultPath, "private configuration path")
	listen := f.String("listen", "", "numeric loopback listen address; default chooses a private port")
	origin := f.String("external-origin", "", "trusted HTTPS proxy origin")
	socket := f.String("broker-socket", "", "privileged broker Unix socket")
	var roots, identities stringsFlag
	f.Var(&roots, "project-root", "project scan root (repeatable)")
	f.Var(&identities, "tailscale-user", "exact permitted Tailscale login (repeatable)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	cfg, err := config.Load(*path)
	if errors.Is(err, os.ErrNotExist) && (args[0] == "init" || args[0] == "install") {
		cfg, err = config.Defaults()
	}
	if err != nil {
		return fmt.Errorf("load configuration (run hostdesk init first): %w", err)
	}
	if args[0] == "init" || args[0] == "install" {
		if os.Geteuid() == 0 {
			return errors.New("run init/install as the owner, not root; install-broker is the separate privileged command")
		}
		if *listen != "" {
			cfg.Listen = *listen
		}
		if *origin != "" {
			cfg.ExternalOrigin = *origin
		}
		if *socket != "" {
			cfg.BrokerSocket = *socket
		}
		if len(roots) > 0 {
			cfg.ProjectRoots = []string(roots)
		}
		if len(identities) > 0 {
			cfg.AllowedTailscaleUsers = []string(identities)
		}
		if err := config.Save(*path, cfg); err != nil {
			return err
		}
		fmt.Println("Private configuration:", *path)
		if args[0] == "install" {
			return installUser(ctx, *path, cfg)
		}
		return nil
	}
	if *listen != "" || *origin != "" || *socket != "" || len(roots) > 0 || len(identities) > 0 {
		return errors.New("configuration flags apply only to init/install")
	}
	switch args[0] {
	case "serve":
		if os.Geteuid() == 0 {
			return errors.New("web server must not run as root")
		}
		return webserver.Serve(ctx, cfg)
	case "inventory":
		collector := discovery.Collector{ProjectRoots: cfg.ProjectRoots}
		if cfg.BrokerSocket != "" {
			c := &broker.Client{Socket: cfg.BrokerSocket}
			collector.Privileged = c.Snapshot
		}
		return encode(collector.Collect(ctx))
	case "address":
		b, e := os.ReadFile(filepath.Join(cfg.StateDir, "listen.json"))
		if e != nil {
			return e
		}
		_, e = os.Stdout.Write(b)
		return e
	case "token":
		p := filepath.Join(cfg.StateDir, "token")
		info, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("token file is not private")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		fmt.Println(strings.TrimSpace(string(b)))
		return nil
	default:
		return fmt.Errorf("unknown command %q (use hostdesk help)", args[0])
	}
}

func encode(v any) error { e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); return e.Encode(v) }
func usage() {
	fmt.Print(`Hostdesk — private Linux service and network inventory

Commands:
  init             Create/update private per-user configuration
  serve            Run the loopback-only dashboard
  inventory        Print actual discovery as JSON (contains private host data)
  address          Print the actual local dashboard address
  token            Print the private owner login token to your terminal
  install          Install and start a systemd user service
  install-broker   Install root broker; requires sudo and an explicit owner UID
  broker           Run the broker (normally systemd-managed)
  version          Print build version

Run a command with --help for its flags. Discovery grants no root control.
Configuration and runtime output must not be committed or published.
`)
}

func unitQuote(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

func copyExecutable(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	src, err = filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	if src == dst {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	if err = os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	out, err := os.CreateTemp(dir, ".hostdesk-install-")
	if err != nil {
		return err
	}
	n := out.Name()
	defer os.Remove(n)
	if _, err = io.Copy(out, in); err == nil {
		err = out.Chmod(0755)
	}
	if err == nil {
		err = out.Sync()
	}
	e := out.Close()
	if err != nil {
		return err
	}
	if e != nil {
		return e
	}
	return os.Rename(n, dst)
}

func command(ctx context.Context, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func installUser(ctx context.Context, path string, cfg config.Config) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	bin := filepath.Join(home, ".local", "bin", "hostdesk")
	if err = copyExecutable(bin); err != nil {
		return err
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(base, "systemd", "user")
	if err = os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err = os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	unit := "[Unit]\nDescription=Hostdesk private Linux service desk\nAfter=default.target\n\n[Service]\nType=simple\nExecStart=" + unitQuote(bin) + " serve --config " + unitQuote(path) + "\nRestart=on-failure\nRestartSec=3\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=" + unitQuote(cfg.StateDir) + "\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\n[Install]\nWantedBy=default.target\n"
	if err = writeUnit(filepath.Join(dir, "hostdesk.service"), unit); err != nil {
		return err
	}
	if err = command(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if err = command(ctx, "systemctl", "--user", "enable", "hostdesk.service"); err != nil {
		return err
	}
	if err = command(ctx, "systemctl", "--user", "restart", "hostdesk.service"); err != nil {
		return err
	}
	fmt.Println("Installed user service. Use hostdesk address and hostdesk token. For boot without a login, enable linger for this owner with loginctl.")
	return nil
}

func writeUnit(path, content string) error {
	if strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("invalid unit path")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("refusing non-regular unit file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

func installBroker(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("install-broker", flag.ContinueOnError)
	uid := f.Int("uid", -1, "owner UID permitted to use the broker (required)")
	var units, containers, ports stringsFlag
	f.Var(&units, "allow-unit", "system service unit allowed for lifecycle control (repeatable)")
	f.Var(&containers, "allow-container", "container ID or name allowed for lifecycle control (repeatable)")
	f.Var(&ports, "protect-port", "TCP management port that policy changes cannot remove (repeatable)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("install-broker requires root")
	}
	if *uid <= 0 {
		return errors.New("--uid must identify the non-root dashboard owner")
	}
	if _, err := user.LookupId(strconv.Itoa(*uid)); err != nil {
		return fmt.Errorf("owner UID: %w", err)
	}
	path := "/etc/hostdesk/broker.json"
	policy := config.BrokerPolicy{AllowedUID: *uid, Socket: "/run/hostdesk/broker.sock", StateDir: "/var/lib/hostdesk", AllowedSystemUnits: []string{}, AllowedContainers: []string{}, ProtectedTCPPorts: []int{}, InitialNetworkPolicy: model.NetworkPolicy{Interfaces: []model.InterfacePolicy{}}}
	if b, err := os.ReadFile(path); err == nil {
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("existing broker policy is not private regular file")
		}
		if err = json.Unmarshal(b, &policy); err != nil {
			return err
		}
		if policy.AllowedUID != *uid {
			return errors.New("existing broker owner differs; review root policy before changing ownership")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(units) > 0 {
		policy.AllowedSystemUnits = []string(units)
	}
	if len(containers) > 0 {
		policy.AllowedContainers = []string(containers)
	}
	if len(ports) > 0 {
		policy.ProtectedTCPPorts = nil
		for _, s := range ports {
			p, e := strconv.Atoi(s)
			if e != nil || p < 1 || p > 65535 {
				return errors.New("protect-port must be 1..65535")
			}
			policy.ProtectedTCPPorts = append(policy.ProtectedTCPPorts, p)
		}
	}
	for _, u := range policy.AllowedSystemUnits {
		if !strings.HasSuffix(u, ".service") || strings.ContainsAny(u, "/\x00\r\n \t") || strings.HasPrefix(u, "-") {
			return errors.New("allow-unit must name a service unit, not a path")
		}
	}
	if !filepath.IsAbs(policy.StateDir) || !filepath.IsAbs(policy.Socket) || strings.ContainsAny(policy.StateDir+policy.Socket, "\x00\r\n") {
		return errors.New("broker state and socket paths must be absolute and contain no control characters")
	}
	if err := config.WritePrivateJSON(path, policy); err != nil {
		return err
	}
	if err := os.MkdirAll(policy.StateDir, 0700); err != nil {
		return err
	}
	bin := "/usr/local/libexec/hostdesk"
	if err := copyExecutable(bin); err != nil {
		return err
	}
	unit := "[Unit]\nDescription=Hostdesk allowlisted privileged broker\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=" + bin + " broker --policy " + path + "\nEnvironment=PATH=/usr/sbin:/usr/bin:/sbin:/bin\nRestart=on-failure\nRestartSec=2\nRuntimeDirectory=hostdesk\nRuntimeDirectoryMode=0711\nRuntimeDirectoryPreserve=restart\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=" + unitQuote(policy.StateDir) + " " + unitQuote(filepath.Dir(policy.Socket)) + "\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := writeUnit("/etc/systemd/system/hostdesk-broker.service", unit); err != nil {
		return err
	}
	if err := command(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := command(ctx, "systemctl", "enable", "hostdesk-broker.service"); err != nil {
		return err
	}
	if err := command(ctx, "systemctl", "restart", "hostdesk-broker.service"); err != nil {
		return err
	}
	fmt.Println("Broker installed with explicit root policy:", path)
	fmt.Println("Connect the owner configuration using hostdesk init --broker-socket", policy.Socket)
	return nil
}
