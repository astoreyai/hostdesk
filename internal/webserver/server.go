package webserver

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/astoreyai/hostdesk/internal/broker"
	"github.com/astoreyai/hostdesk/internal/config"
	"github.com/astoreyai/hostdesk/internal/discovery"
	"github.com/astoreyai/hostdesk/internal/model"
)

//go:embed assets/*
var assets embed.FS

const sessionLifetime = 8 * time.Hour

// Serve exposes the local control plane. Remote access must terminate at an
// explicitly configured proxy; arbitrary forwarded headers never change trust.
func Serve(ctx context.Context, cfg config.Config) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen must be a numeric loopback address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen must use a numeric loopback address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return errors.New("listen must use a numeric port from 0 to 65535")
	}
	cfg.Listen = net.JoinHostPort(host, strconv.Itoa(portNumber))
	external, err := parseExternalOrigin(cfg.ExternalOrigin)
	if err != nil {
		return err
	}
	if len(cfg.AllowedTailscaleUsers) != 0 && external == nil {
		return errors.New("Tailscale identity requires an explicit external origin")
	}
	if len(cfg.AllowedTailscaleUsers) > 256 {
		return errors.New("at most 256 Tailscale identities may be configured")
	}
	if cfg.RefreshSeconds <= 0 {
		cfg.RefreshSeconds = 15
	}
	if cfg.RefreshSeconds > 3600 {
		return errors.New("refreshSeconds must not exceed 3600")
	}
	if err := prepareState(cfg.StateDir); err != nil {
		return err
	}
	lock, err := lockState(cfg.StateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	token, err := ownerToken(cfg.StateDir)
	if err != nil {
		return err
	}
	audit, err := openAudit(cfg.StateDir)
	if err != nil {
		return err
	}
	defer audit.close()
	listenAddress, err := persistedListen(cfg.StateDir, cfg.Listen)
	if err != nil {
		return err
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	address := listener.Addr().String()
	origin := "http://" + address
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &server{
		ctx: serveCtx, cfg: cfg, origin: origin, external: external,
		ownerToken: token, audit: audit,
		sessions: make(map[[32]byte]*session), proxySessions: make(map[string]*session),
		approvals: make(map[string]actionApproval), rates: make(map[string]*rateBucket),
		allowedUsers: make(map[string]bool),
	}
	s.static = make(map[string]staticAsset, 4)
	for _, item := range []struct{ name, contentType string }{
		{"index.html", "text/html; charset=utf-8"},
		{"app.js", "text/javascript; charset=utf-8"},
		{"style.css", "text/css; charset=utf-8"},
	} {
		data, err := assets.ReadFile("assets/" + item.name)
		if err != nil {
			return fmt.Errorf("load embedded application asset: %w", err)
		}
		s.static["/"+item.name] = staticAsset{data, item.contentType}
	}
	s.static["/"] = s.static["/index.html"]
	for _, user := range cfg.AllowedTailscaleUsers {
		if user == "" || len(user) > 256 || strings.TrimSpace(user) != user || strings.ContainsAny(user, "\r\n\x00") {
			return errors.New("allowed Tailscale identities must be exact nonempty login names")
		}
		s.allowedUsers[user] = true
	}
	if cfg.BrokerSocket != "" {
		s.broker = &broker.Client{Socket: cfg.BrokerSocket}
	}
	s.collector = &discovery.Collector{ProjectRoots: cfg.ProjectRoots, Privileged: s.privilegedSnapshot}
	if err := writePrivateJSON(filepath.Join(cfg.StateDir, "listen.json"), struct {
		Address string `json:"address"`
		Origin  string `json:"origin"`
	}{address, origin}); err != nil {
		return err
	}

	httpServer := &http.Server{
		Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return serveCtx },
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-serveCtx.Done()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			_ = httpServer.Close()
		}
	}()
	err = httpServer.Serve(listener)
	cancel()
	<-shutdownDone
	// Collection creation holds cacheMu while checking the lifetime context.
	// This barrier keeps Wait from racing a last pre-cancellation Add.
	s.cacheMu.Lock()
	s.cacheMu.Unlock()
	s.work.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type staticAsset struct {
	data        []byte
	contentType string
}

type server struct {
	ctx          context.Context
	cfg          config.Config
	origin       string
	external     *url.URL
	ownerToken   string
	allowedUsers map[string]bool
	broker       *broker.Client
	collector    *discovery.Collector
	audit        *auditLog
	static       map[string]staticAsset
	work         sync.WaitGroup

	authMu        sync.Mutex
	sessions      map[[32]byte]*session
	proxySessions map[string]*session
	rates         map[string]*rateBucket

	cacheMu         sync.Mutex
	cached          *model.Snapshot
	cacheTime       time.Time
	cacheEpoch      uint64
	collecting      chan struct{}
	brokerAvailable bool
	brokerChecked   time.Time
	brokerChecking  chan struct{}

	approvalMu sync.Mutex
	approvals  map[string]actionApproval
	actionMu   sync.Mutex
}

func parseExternalOrigin(value string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	u, err := url.Parse(value)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.Opaque != "" || strings.ContainsAny(u.Host, "\\\r\n\t ") {
		return nil, errors.New("externalOrigin must be an exact HTTPS origin without a path, credentials, query, or fragment")
	}
	if u.Hostname() == "" {
		return nil, errors.New("externalOrigin has no hostname")
	}
	return u, nil
}

func (s *server) requestOrigin(r *http.Request) (string, bool) {
	if r.Host == strings.TrimPrefix(s.origin, "http://") {
		return s.origin, true
	}
	if s.external != nil && r.Host == s.external.Host {
		return s.external.String(), true
	}
	return "", false
}

func loopbackPeer(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	if !loopbackPeer(r.RemoteAddr) {
		apiError(w, 403, "forbidden", "Only loopback connections are accepted.")
		return
	}
	origin, ok := s.requestOrigin(r)
	if !ok {
		apiError(w, 403, "forbidden", "Unrecognized request host.")
		return
	}
	if r.URL.RawPath != "" || strings.Contains(r.URL.Path, "//") {
		apiError(w, 404, "not_found", "Not found.")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.serveAPI(w, r, origin)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		apiError(w, 405, "method", "Method not allowed.")
		return
	}
	asset, exists := s.static[r.URL.Path]
	if !exists {
		apiError(w, 404, "not_found", "Not found.")
		return
	}
	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(asset.data)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(asset.data)
	}
}
