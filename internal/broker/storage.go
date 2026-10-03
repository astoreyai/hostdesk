package broker

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/astoreyai/hostdesk/internal/config"
	"github.com/astoreyai/hostdesk/internal/model"
)

type pendingState struct {
	Token              string              `json:"token"`
	Actor              string              `json:"actor"`
	ExpiresAt          time.Time           `json:"expiresAt"`
	PreviousTable      string              `json:"previousTable"`
	Policy             model.NetworkPolicy `json:"policy"`
	AppliedFingerprint string              `json:"appliedFingerprint"`
	PeerPorts          []int               `json:"peerPorts"`
	ManagementPorts    []int               `json:"managementPorts"`
}

type durableState struct {
	Version         int                 `json:"version"`
	Revision        string              `json:"revision"`
	Policy          model.NetworkPolicy `json:"policy"`
	Applied         bool                `json:"applied"`
	PeerPorts       []int               `json:"peerPorts"`
	ManagementPorts []int               `json:"managementPorts"`
	Pending         *pendingState       `json:"pending,omitempty"`
}

func loadPolicy(path string) (config.BrokerPolicy, error) {
	var policy config.BrokerPolicy
	if err := rootPath(path, false, false); err != nil {
		return policy, fmt.Errorf("broker policy is not secure: %w", err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return policy, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if err := decodeStrict(io.LimitReader(file, 1<<20), &policy); err != nil {
		return policy, fmt.Errorf("invalid broker policy: %w", err)
	}
	if policy.AllowedUID < 0 || uint64(policy.AllowedUID) > uint64(^uint32(0)) {
		return policy, fmt.Errorf("invalid allowed UID")
	}
	if policy.Socket == "" || len(policy.Socket) > 100 || !filepath.IsAbs(policy.Socket) || filepath.Clean(policy.Socket) != policy.Socket {
		return policy, fmt.Errorf("invalid broker socket path")
	}
	if policy.StateDir == "/" || policy.StateDir == "" {
		return policy, fmt.Errorf("invalid state directory")
	}
	for _, unit := range policy.AllowedSystemUnits {
		if !validUnit(unit) {
			return policy, fmt.Errorf("invalid allowed system unit")
		}
	}
	for _, name := range policy.AllowedContainers {
		if !validContainerName(name) {
			return policy, fmt.Errorf("invalid allowed container")
		}
	}
	if _, err := normalizePorts(policy.ProtectedTCPPorts); err != nil {
		return policy, err
	}
	return policy, nil
}

func decodeStrict(reader io.Reader, value any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON value")
	}
	return nil
}

func (b *service) loadState() error {
	path := filepath.Join(b.policy.StateDir, "network.json")
	file, err := openPrivate(path, syscall.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		revision, err := randomToken()
		if err != nil {
			return err
		}
		b.state = durableState{Version: 1, Revision: revision, Policy: b.policy.InitialNetworkPolicy}
		if b.state.Policy.Interfaces == nil {
			b.state.Policy.Interfaces = []model.InterfacePolicy{}
		}
		return b.saveState(b.state)
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if err := decodeStrict(io.LimitReader(file, 16<<20), &b.state); err != nil {
		return err
	}
	if b.state.Version != 1 || !fullIDPattern.MatchString(b.state.Revision) {
		return fmt.Errorf("unsupported or invalid broker state")
	}
	if b.state.Policy.Interfaces == nil {
		return fmt.Errorf("broker state has no explicit policy")
	}
	if _, err := normalizePolicy(b.state.Policy, nil, false); err != nil {
		return fmt.Errorf("invalid persisted policy")
	}
	if _, err := normalizePorts(b.state.PeerPorts); err != nil {
		return fmt.Errorf("invalid persisted peer API ports")
	}
	if _, err := normalizePorts(b.state.ManagementPorts); err != nil {
		return fmt.Errorf("invalid persisted management ports")
	}
	if pending := b.state.Pending; pending != nil {
		if !fullIDPattern.MatchString(pending.Token) || pending.ExpiresAt.IsZero() || validateActor(pending.Actor) != nil || pending.Policy.Interfaces == nil {
			return fmt.Errorf("invalid pending recovery state")
		}
		if pending.AppliedFingerprint != "" && !fullIDPattern.MatchString(pending.AppliedFingerprint) {
			return fmt.Errorf("invalid pending firewall fingerprint")
		}
		if _, err := normalizePolicy(pending.Policy, nil, false); err != nil {
			return fmt.Errorf("invalid pending policy")
		}
		if _, err := normalizePorts(pending.PeerPorts); err != nil {
			return fmt.Errorf("invalid pending peer API ports")
		}
		if _, err := normalizePorts(pending.ManagementPorts); err != nil {
			return fmt.Errorf("invalid pending management ports")
		}
	}
	return nil
}

// Confirmed and pending data share one rename commit. A crash can therefore
// never expose a confirmed policy alongside a stale rollback journal.
func (b *service) saveState(state durableState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := rootPath(b.policy.StateDir, true, true); err != nil {
		return err
	}
	destination := filepath.Join(b.policy.StateDir, "network.json")
	if err := rootPath(destination, false, true); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(b.policy.StateDir, ".network-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, destination); err != nil {
		return err
	}
	dir, err := os.Open(b.policy.StateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (b *service) audit(actor, operation, target string, success bool, detail string) error {
	b.auditMu.Lock()
	defer b.auditMu.Unlock()
	path := filepath.Join(b.policy.StateDir, "audit.jsonl")
	file, err := openPrivate(path, syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT)
	if err != nil {
		return unavailable("private audit is unavailable")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return unavailable("private audit is unavailable")
	}
	if info.Size() > 0 {
		var last [1]byte
		if _, err := file.ReadAt(last[:], info.Size()-1); err != nil || last[0] != '\n' {
			file.Close()
			return unavailable("private audit has an incomplete trailing entry; root repair is required")
		}
	}
	if info.Size() > 8<<20 {
		file.Close()
		previous := filepath.Join(b.policy.StateDir, "audit.previous.jsonl")
		if err := rootPath(previous, false, true); err != nil && !errors.Is(err, os.ErrNotExist) {
			return unavailable("private audit rotation is unavailable")
		}
		if err := os.Rename(path, previous); err != nil {
			return unavailable("private audit rotation is unavailable")
		}
		file, err = openPrivate(path, syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT)
		if err != nil {
			return unavailable("private audit is unavailable")
		}
	}
	defer file.Close()
	entry := model.AuditEntry{Time: time.Now().UTC(), Actor: actor, Operation: operation, Target: target, Success: success, Detail: detail}
	if err := json.NewEncoder(file).Encode(entry); err != nil {
		return unavailable("private audit write failed")
	}
	if err := file.Sync(); err != nil {
		return unavailable("private audit sync failed")
	}
	dir, err := os.Open(b.policy.StateDir)
	if err != nil {
		return unavailable("private audit directory is unavailable")
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return unavailable("private audit directory sync failed")
	}
	return nil
}

func (b *service) auditEntries() ([]model.AuditEntry, error) {
	b.auditMu.Lock()
	defer b.auditMu.Unlock()
	entries := make([]model.AuditEntry, 0, 200)
	for _, name := range []string{"audit.previous.jsonl", "audit.jsonl"} {
		file, err := openPrivate(filepath.Join(b.policy.StateDir, name), syscall.O_RDONLY)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, unavailable("private audit is unavailable")
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 10<<20))
		scanner.Buffer(make([]byte, 4096), 65536)
		for scanner.Scan() {
			var entry model.AuditEntry
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				file.Close()
				return nil, unavailable("private audit contains an incomplete entry")
			}
			if len(entries) == 200 {
				copy(entries, entries[1:])
				entries = entries[:199]
			}
			entries = append(entries, entry)
		}
		err = scanner.Err()
		file.Close()
		if err != nil {
			return nil, unavailable("private audit read failed")
		}
	}
	return entries, nil
}
