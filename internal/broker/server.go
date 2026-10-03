package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/astoreyai/hostdesk/internal/config"
	"github.com/astoreyai/hostdesk/internal/model"
)

type service struct {
	policy               config.BrokerPolicy
	mu                   sync.Mutex
	actionMu             sync.Mutex
	inventoryMu          sync.Mutex
	auditMu              sync.Mutex
	state                durableState
	previews             map[string]policyPreview
	runtimeRules         string
	installedFingerprint string
	networkError         string
}

type peerContextKey struct{}
type peerConnection struct {
	net.Conn
	uid uint32
}
type peerListener struct {
	*net.UnixListener
	allowed uint32
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		raw, err := connection.SyscallConn()
		if err != nil {
			connection.Close()
			continue
		}
		var credential *syscall.Ucred
		var credentialErr error
		if err := raw.Control(func(fd uintptr) {
			credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		}); err != nil || credentialErr != nil || credential == nil || (credential.Uid != 0 && credential.Uid != l.allowed) {
			connection.Close()
			continue
		}
		return &peerConnection{Conn: connection, uid: credential.Uid}, nil
	}
}

// Serve runs only as root. The application-facing process gets a narrow Unix
// capability, never a shell, arbitrary executable, arbitrary file, or nft script.
func Serve(ctx context.Context, policyPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("broker requires root")
	}
	policy, err := loadPolicy(policyPath)
	if err != nil {
		return err
	}
	if err := ensureRootDir(policy.StateDir, true); err != nil {
		return fmt.Errorf("insecure broker state directory: %w", err)
	}
	if err := ensureRootDir(filepath.Dir(policy.Socket), false); err != nil {
		return fmt.Errorf("insecure broker socket directory: %w", err)
	}
	lock, err := openPrivate(filepath.Join(policy.StateDir, "broker.lock"), syscall.O_RDWR|syscall.O_CREAT)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another broker holds the state lock")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	b := &service{policy: policy, previews: make(map[string]policyPreview)}
	if err := b.loadState(); err != nil {
		return fmt.Errorf("cannot load secure network state: %w", err)
	}
	// Recovery is deliberately before binding the socket: no request may confirm
	// an unconfirmed policy inherited from a dead process.
	if b.state.Pending != nil {
		if err := b.rollbackLocked("broker", "crash recovery rollback"); err != nil {
			return err
		}
	}
	if err := b.audit("broker", "broker.start", "broker", true, "root broker starting"); err != nil {
		return err
	}
	if err := b.reconcileConfirmed(ctx, true); err != nil {
		b.networkError = err.Error()
	}
	if info, err := os.Lstat(policy.Socket); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || (stat.Uid != 0 && stat.Uid != uint32(policy.AllowedUID)) {
			return fmt.Errorf("refusing to replace an unexpected socket path")
		}
		connection, dialErr := net.DialTimeout("unix", policy.Socket, time.Second)
		if dialErr == nil {
			connection.Close()
			return fmt.Errorf("broker socket is already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			return fmt.Errorf("existing broker socket cannot be safely replaced")
		}
		if err := os.Remove(policy.Socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: policy.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	defer os.Remove(policy.Socket)
	if err := os.Chmod(policy.Socket, 0600); err != nil {
		return err
	}
	if err := os.Chown(policy.Socket, policy.AllowedUID, -1); err != nil {
		return err
	}
	server := &http.Server{
		Handler:           b,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       45 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(parent context.Context, conn net.Conn) context.Context {
			return context.WithValue(parent, peerContextKey{}, conn.(*peerConnection).uid)
		},
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	stopped := make(chan struct{})
	defer close(stopped)
	maintenanceDone := make(chan struct{})
	go func() { defer close(maintenanceDone); b.maintain(work) }()
	go func() {
		select {
		case <-ctx.Done():
			shutdown, finish := context.WithTimeout(context.Background(), 5*time.Second)
			defer finish()
			server.Shutdown(shutdown)
		case <-stopped:
		}
	}()
	err = server.Serve(&peerListener{UnixListener: listener, allowed: uint32(policy.AllowedUID)})
	cancel()
	shutdown, finish := context.WithTimeout(context.Background(), 85*time.Second)
	shutdownErr := server.Shutdown(shutdown)
	finish()
	if shutdownErr != nil {
		server.Close()
	}
	<-maintenanceDone
	// Graceful shutdown also restores temporary changes rather than waiting for
	// the next process to recover them. Confirmed policy remains installed.
	b.mu.Lock()
	rollbackErr := b.rollbackLocked("broker", "broker shutdown rollback")
	b.mu.Unlock()
	if rollbackErr != nil {
		return rollbackErr
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type actionEnvelope struct {
	Actor   string              `json:"actor"`
	Request model.ActionRequest `json:"request"`
}
type policyEnvelope struct {
	Actor   string              `json:"actor"`
	Request model.PolicyRequest `json:"request"`
}
type applyEnvelope struct {
	Actor   string             `json:"actor"`
	Request model.ApplyRequest `json:"request"`
}
type tokenEnvelope struct {
	Actor string `json:"actor"`
	Token string `json:"token"`
}

func body(request *http.Request, writer http.ResponseWriter, target any) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return invalid("Content-Type must be application/json")
	}
	reader := http.MaxBytesReader(writer, request.Body, 1<<20)
	defer reader.Close()
	if err := decodeStrict(reader, target); err != nil {
		return invalid("invalid or oversized JSON request")
	}
	return nil
}

func send(writer http.ResponseWriter, value any, err error) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if err != nil {
		var apiError *Error
		if !errors.As(err, &apiError) {
			apiError = &Error{Status: 500, Code: "internal", Message: "broker operation failed"}
		}
		writer.WriteHeader(apiError.Status)
		json.NewEncoder(writer).Encode(apiError)
		return
	}
	json.NewEncoder(writer).Encode(value)
}

func (b *service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	uid, ok := request.Context().Value(peerContextKey{}).(uint32)
	if !ok || (uid != 0 && uid != uint32(b.policy.AllowedUID)) {
		send(writer, nil, forbidden("Unix peer is not authorized"))
		return
	}
	if request.URL.RawQuery != "" || request.URL.Fragment != "" {
		send(writer, nil, invalid("query parameters are not supported"))
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 75*time.Second)
	defer cancel()
	switch request.Method + " " + request.URL.Path {
	case "GET /snapshot":
		send(writer, b.snapshot(ctx), nil)
	case "GET /network":
		send(writer, b.network(ctx), nil)
	case "GET /audit":
		value, err := b.auditEntries()
		send(writer, value, err)
	case "POST /action":
		var envelope actionEnvelope
		if err := body(request, writer, &envelope); err != nil {
			send(writer, nil, err)
			return
		}
		err := b.action(ctx, envelope.Request, envelope.Actor)
		send(writer, struct {
			OK bool `json:"ok"`
		}{OK: err == nil}, err)
	case "POST /network/preview":
		var envelope policyEnvelope
		if err := body(request, writer, &envelope); err != nil {
			send(writer, nil, err)
			return
		}
		value, err := b.previewPolicy(ctx, envelope.Request, envelope.Actor)
		send(writer, value, err)
	case "POST /network/apply":
		var envelope applyEnvelope
		if err := body(request, writer, &envelope); err != nil {
			send(writer, nil, err)
			return
		}
		value, err := b.applyPolicy(ctx, envelope.Request, envelope.Actor)
		send(writer, value, err)
	case "POST /network/confirm", "POST /network/rollback":
		var envelope tokenEnvelope
		if err := body(request, writer, &envelope); err != nil {
			send(writer, nil, err)
			return
		}
		var value model.NetworkState
		var err error
		if request.URL.Path == "/network/confirm" {
			value, err = b.confirmPolicy(ctx, envelope.Token, envelope.Actor)
		} else {
			value, err = b.rollbackPolicy(ctx, envelope.Token, envelope.Actor)
		}
		send(writer, value, err)
	default:
		io.Copy(io.Discard, io.LimitReader(request.Body, 1024))
		send(writer, nil, failure(404, "not_found", "unknown broker endpoint or method"))
	}
}
