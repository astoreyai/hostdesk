package broker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/astoreyai/hostdesk/internal/model"
)

const rollbackWindow = 90 * time.Second
const previewWindow = 2 * time.Minute

type policyPreview struct {
	actor        string
	revision     string
	policy       model.NetworkPolicy
	rules        string
	confirmation string
	expires      time.Time
}

func (b *service) networkLocked(ctx context.Context) model.NetworkState {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	state := model.NetworkState{Policy: b.state.Policy, ProtectedTCPPorts: []int{}, Revision: b.state.Revision}
	if b.state.Pending != nil {
		state.Policy = b.state.Pending.Policy
		state.Pending = &model.PendingPolicy{Token: b.state.Pending.Token, ExpiresAt: b.state.Pending.ExpiresAt}
	}
	table, err := inspectTable(ctx)
	if err != nil {
		state.Error = err.Error()
		return state
	}
	state.Rules = table.text
	state.Revision = fingerprint(b.state.Revision + ":" + table.fingerprint)
	protected, err := b.protectedPorts(ctx)
	if err != nil {
		state.Error = err.Error()
		return state
	}
	state.ProtectedTCPPorts = protected
	if b.networkError != "" {
		state.Error = b.networkError
		return state
	}
	if !b.state.Applied && b.state.Pending == nil && table.text != "" {
		state.Error = "the reserved nftables table exists without confirmed broker state; root administrator reconciliation is required"
		return state
	}
	state.Available = true
	return state
}

func (b *service) network(ctx context.Context) model.NetworkState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.networkLocked(ctx)
}

func (b *service) previewPolicy(ctx context.Context, req model.PolicyRequest, actor string) (model.Preview, error) {
	if err := validateActor(actor); err != nil {
		return model.Preview{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.networkLocked(ctx)
	if !state.Available {
		return model.Preview{}, unavailable(state.Error)
	}
	if b.state.Pending != nil {
		return model.Preview{}, stale("a policy is awaiting confirmation or rollback")
	}
	if req.Revision != state.Revision {
		return model.Preview{}, stale("network revision changed; refresh and preview again")
	}
	policy, err := validatePolicy(req.Policy, state.ProtectedTCPPorts)
	if err != nil {
		return model.Preview{}, err
	}
	peers, err := peerAPIPorts(ctx, policy)
	if err != nil {
		return model.Preview{}, err
	}
	rules := renderTable(policy, peers)
	table, err := inspectTable(ctx)
	if err != nil {
		return model.Preview{}, err
	}
	if fingerprint(b.state.Revision+":"+table.fingerprint) != req.Revision {
		return model.Preview{}, stale("firewall changed during preview")
	}
	script := transaction(table, rules)
	if err := checkTransaction(ctx, script); err != nil {
		return model.Preview{}, err
	}
	token, err := randomToken()
	if err != nil {
		return model.Preview{}, err
	}
	expires := time.Now().UTC().Add(previewWindow)
	confirmation := "APPLY " + token[:12]
	for key, preview := range b.previews {
		if time.Now().After(preview.expires) {
			delete(b.previews, key)
		}
	}
	if len(b.previews) >= 128 {
		return model.Preview{}, failure(429, "rate_limited", "too many outstanding policy previews")
	}
	b.previews[token] = policyPreview{actor: actor, revision: req.Revision, policy: policy, rules: rules, confirmation: confirmation, expires: expires}
	warnings := []string{
		"Only NEW inbound TCP/UDP on the selected interfaces is filtered. Established connections, loopback and ICMP remain intact.",
		"Allowed traffic still traverses later host firewall rules. This does not publish routes or change Docker forwarding.",
		"Unconfirmed changes roll back automatically after 90 seconds, including after a broker restart.",
		"Confirm from a live connection after checking access; an existing connection alone does not prove new connections are allowed.",
	}
	if err := b.audit(actor, "network.preview", tableName, true, "policy validated; no firewall changes"); err != nil {
		delete(b.previews, token)
		return model.Preview{}, err
	}
	return model.Preview{Token: token, Summary: fmt.Sprintf("Replace Hostdesk inbound policy for %d interface(s)", len(policy.Interfaces)), Confirmation: confirmation, Warnings: warnings, ExpiresAt: expires, Rules: script}, nil
}

func (b *service) applyPolicy(ctx context.Context, req model.ApplyRequest, actor string) (model.NetworkState, error) {
	if err := validateActor(actor); err != nil {
		return model.NetworkState{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	preview, ok := b.previews[req.Token]
	if !ok {
		return model.NetworkState{}, stale("preview is unknown or was already used")
	}
	if preview.actor != actor {
		return model.NetworkState{}, forbidden("preview belongs to a different actor")
	}
	delete(b.previews, req.Token)
	if time.Now().After(preview.expires) {
		return model.NetworkState{}, stale("preview expired")
	}
	if req.Confirmation != preview.confirmation {
		return model.NetworkState{}, invalid("confirmation text does not match; create a new preview")
	}
	state := b.networkLocked(ctx)
	if !state.Available {
		return model.NetworkState{}, unavailable(state.Error)
	}
	if b.state.Pending != nil || state.Revision != preview.revision {
		return model.NetworkState{}, stale("network state changed; create a new preview")
	}
	policy, err := validatePolicy(preview.policy, state.ProtectedTCPPorts)
	if err != nil {
		return model.NetworkState{}, err
	}
	peers, err := peerAPIPorts(ctx, policy)
	if err != nil {
		return model.NetworkState{}, err
	}
	rules := renderTable(policy, peers)
	if rules != preview.rules {
		return model.NetworkState{}, stale("runtime-derived ports changed; create a new preview")
	}
	current, err := inspectTable(ctx)
	if err != nil {
		return model.NetworkState{}, err
	}
	if fingerprint(b.state.Revision+":"+current.fingerprint) != preview.revision {
		return model.NetworkState{}, stale("firewall changed since preview")
	}
	if err := checkTransaction(ctx, transaction(current, rules)); err != nil {
		return model.NetworkState{}, err
	}
	token, err := randomToken()
	if err != nil {
		return model.NetworkState{}, err
	}
	revision, err := randomToken()
	if err != nil {
		return model.NetworkState{}, err
	}
	if err := b.audit(actor, "network.apply", tableName, false, "policy apply requested; durable rollback will precede changes"); err != nil {
		return model.NetworkState{}, err
	}
	next := b.state
	next.Revision = revision
	next.Pending = &pendingState{Token: token, Actor: actor, ExpiresAt: time.Now().UTC().Add(rollbackWindow), PreviousTable: current.text, Policy: policy, PeerPorts: peers, ManagementPorts: state.ProtectedTCPPorts}
	if err := b.saveState(next); err != nil {
		return model.NetworkState{}, unavailable("cannot persist rollback state; no changes were made")
	}
	b.state = next
	// A disconnected caller must not leave an interrupted recovery path. The
	// durable pending marker already guarantees recovery if this process exits.
	operation, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := applyTransaction(operation, current, rules); err != nil {
		if rollbackErr := b.rollbackLocked("broker", "failed apply recovery"); rollbackErr != nil {
			return model.NetworkState{}, rollbackErr
		}
		return model.NetworkState{}, err
	}
	applied, err := inspectTable(operation)
	if err != nil {
		b.networkError = "applied policy could not be inspected; automatic rollback remains armed"
		return model.NetworkState{}, err
	}
	next = b.state
	pending := *next.Pending
	pending.AppliedFingerprint = applied.fingerprint
	next.Pending = &pending
	if err := b.saveState(next); err != nil {
		b.networkError = "applied policy state could not be saved; automatic rollback remains armed"
		return model.NetworkState{}, unavailable(b.networkError)
	}
	b.state = next
	b.runtimeRules = rules
	b.installedFingerprint = applied.fingerprint
	if err := b.audit(actor, "network.apply", tableName, true, "policy active temporarily; explicit confirmation required"); err != nil {
		return model.NetworkState{}, err
	}
	return b.networkLocked(operation), nil
}

func (b *service) confirmPolicy(ctx context.Context, token, actor string) (model.NetworkState, error) {
	if err := validateActor(actor); err != nil {
		return model.NetworkState{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	pending := b.state.Pending
	if pending == nil || token != pending.Token {
		return model.NetworkState{}, stale("no matching pending policy")
	}
	if actor != pending.Actor {
		return model.NetworkState{}, forbidden("pending policy belongs to a different actor")
	}
	if time.Now().After(pending.ExpiresAt) {
		if err := b.rollbackLocked("broker", "confirmation arrived after deadline"); err != nil {
			return model.NetworkState{}, err
		}
		return model.NetworkState{}, stale("confirmation deadline passed; policy rolled back")
	}
	if ctx.Err() != nil {
		return model.NetworkState{}, stale("confirmation connection is no longer live")
	}
	current, err := inspectTable(ctx)
	if err != nil {
		return model.NetworkState{}, err
	}
	if pending.AppliedFingerprint == "" || current.fingerprint != pending.AppliedFingerprint {
		return model.NetworkState{}, stale("temporary firewall changed; roll back instead of confirming")
	}
	if ctx.Err() != nil {
		return model.NetworkState{}, stale("confirmation connection is no longer live")
	}
	if err := b.audit(actor, "network.confirm", tableName, false, "confirmation requested from a live connection"); err != nil {
		return model.NetworkState{}, err
	}
	revision, err := randomToken()
	if err != nil {
		return model.NetworkState{}, err
	}
	next := b.state
	next.Policy = pending.Policy
	next.Applied = true
	next.PeerPorts = pending.PeerPorts
	next.ManagementPorts = pending.ManagementPorts
	next.Pending = nil
	next.Revision = revision
	if time.Now().After(pending.ExpiresAt) || ctx.Err() != nil {
		return model.NetworkState{}, stale("confirmation connection or deadline expired; rollback remains armed")
	}
	if err := b.saveState(next); err != nil {
		if rollbackErr := b.rollbackLocked("broker", "failed confirmation persistence"); rollbackErr != nil {
			return model.NetworkState{}, rollbackErr
		}
		return model.NetworkState{}, unavailable("confirmation could not be persisted; temporary policy was rolled back")
	}
	b.state = next
	b.networkError = ""
	if err := b.audit(actor, "network.confirm", tableName, true, "policy committed; timed rollback canceled"); err != nil {
		return model.NetworkState{}, err
	}
	return b.networkLocked(ctx), nil
}

func (b *service) rollbackPolicy(ctx context.Context, token, actor string) (model.NetworkState, error) {
	if err := validateActor(actor); err != nil {
		return model.NetworkState{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state.Pending == nil || token != b.state.Pending.Token {
		return model.NetworkState{}, stale("no matching pending policy")
	}
	if actor != b.state.Pending.Actor {
		return model.NetworkState{}, forbidden("pending policy belongs to a different actor")
	}
	if err := b.rollbackLocked(actor, "explicit rollback"); err != nil {
		return model.NetworkState{}, err
	}
	return b.networkLocked(ctx), nil
}

func (b *service) rollbackLocked(actor, reason string) error {
	if b.state.Pending == nil {
		return nil
	}
	// Safety recovery proceeds even when an audit device has failed. The durable
	// journal is retained until the firewall restoration and state sync succeed.
	auditErr := b.audit(actor, "network.rollback", tableName, false, reason+" requested")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	current, err := inspectTable(ctx)
	if err == nil {
		err = applyTransaction(ctx, current, b.state.Pending.PreviousTable)
	}
	var restored tableState
	if err == nil {
		restored, err = inspectTable(ctx)
	}
	if err != nil {
		b.networkError = "rollback failed; durable recovery remains pending"
		b.audit(actor, "network.rollback", tableName, false, b.networkError)
		return unavailable(b.networkError)
	}
	revision, err := randomToken()
	if err != nil {
		return err
	}
	next := b.state
	next.Pending = nil
	next.Revision = revision
	if err := b.saveState(next); err != nil {
		b.networkError = "firewall restored but rollback state cannot be persisted"
		return unavailable(b.networkError)
	}
	b.state = next
	b.runtimeRules = ""
	b.installedFingerprint = restored.fingerprint
	b.networkError = ""
	if err := b.audit(actor, "network.rollback", tableName, true, reason+" completed"); err != nil {
		return err
	}
	return auditErr
}

func (b *service) reconcileConfirmed(ctx context.Context, startup bool) error {
	if !b.state.Applied || b.state.Pending != nil {
		return nil
	}
	var diagnostic error
	protected, err := b.protectedPorts(ctx)
	if err != nil {
		diagnostic = unavailable("live SSH inventory is unavailable; retaining previously confirmed management exceptions")
		protected, _ = normalizePorts(append(append([]int(nil), b.state.ManagementPorts...), b.policy.ProtectedTCPPorts...))
	}
	// iifname matches are valid before an interface appears at boot. Existence
	// checks apply only to newly requested policy, not restoration of approval.
	policy, err := normalizePolicy(b.state.Policy, nil, false)
	if err != nil {
		return unavailable("confirmed network policy is invalid")
	}
	for i := range policy.Interfaces {
		policy.Interfaces[i].TCPPorts = append(policy.Interfaces[i].TCPPorts, protected...)
		policy.Interfaces[i].TCPPorts, _ = normalizePorts(policy.Interfaces[i].TCPPorts)
	}
	peers, err := peerAPIPorts(ctx, policy)
	if err != nil {
		diagnostic = unavailable("Tailscale peer API discovery is unavailable; retaining previously confirmed peer API exceptions")
		peers = b.state.PeerPorts
	}
	rules := renderTable(policy, peers)
	if !startup && rules == b.runtimeRules {
		return diagnostic
	}
	current, err := inspectTable(ctx)
	if err != nil {
		return err
	}
	if err := checkTransaction(ctx, transaction(current, rules)); err != nil {
		return err
	}
	if err := b.audit("broker", "network.reconcile", tableName, false, "refreshing confirmed policy runtime ports"); err != nil {
		return err
	}
	if err := applyTransaction(ctx, current, rules); err != nil {
		return err
	}
	installed, err := inspectTable(ctx)
	if err != nil {
		return err
	}
	next := b.state
	next.PeerPorts = peers
	next.ManagementPorts = protected
	if err := b.saveState(next); err != nil {
		return unavailable("refreshed runtime ports could not be persisted")
	}
	b.state = next
	b.runtimeRules = rules
	b.installedFingerprint = installed.fingerprint
	if err := b.audit("broker", "network.reconcile", tableName, true, "confirmed policy and runtime-derived management ports restored"); err != nil {
		return err
	}
	return diagnostic
}

func (b *service) maintain(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	nextRefresh := time.Now().Add(15 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			b.mu.Lock()
			if b.state.Pending != nil && !now.Before(b.state.Pending.ExpiresAt) {
				b.rollbackLocked("broker", "automatic timeout rollback")
			} else if b.state.Pending == nil && !now.Before(nextRefresh) {
				nextRefresh = now.Add(15 * time.Second)
				if err := b.reconcileConfirmed(ctx, false); err != nil {
					b.networkError = strings.TrimSpace(err.Error())
				} else {
					b.networkError = ""
				}
			}
			b.mu.Unlock()
		}
	}
}
