package webserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/astoreyai/hostdesk/internal/discovery"
	"github.com/astoreyai/hostdesk/internal/model"
)

type actionApproval struct {
	Actor        string
	Request      model.ActionRequest
	Fingerprint  [32]byte
	Confirmation string
	Expires      time.Time
}

func validateAction(req model.ActionRequest) error {
	if req.Operation != "start" && req.Operation != "stop" && req.Operation != "restart" {
		return &httpError{400, "validation", "Choose start, stop, or restart."}
	}
	if req.ID == "" || len(req.ID) > 512 || strings.IndexFunc(req.ID, unicode.IsControl) >= 0 {
		return &httpError{400, "validation", "A valid discovered service ID is required."}
	}
	return nil
}

func userService(service model.Service) bool {
	return service.Manager == "systemd" && service.Scope == "user" && strings.HasPrefix(service.ID, "systemd:user:")
}

func (s *server) actionable(ctx context.Context, req model.ActionRequest, applying bool) (*model.Service, error) {
	value, err := s.snapshot(ctx, true)
	if err != nil {
		return nil, err
	}
	for i := range value.Services {
		service := &value.Services[i]
		if service.ID != req.ID {
			continue
		}
		if !userService(*service) {
			s.cacheMu.Lock()
			available := s.brokerAvailable
			s.cacheMu.Unlock()
			if !available {
				return nil, &httpError{503, "unavailable", "The privileged broker is unavailable for this service."}
			}
		}
		for _, permitted := range service.Actions {
			if permitted == req.Operation {
				return service, nil
			}
		}
		if applying {
			return nil, &httpError{409, "stale", "The service permissions changed. Request a new preview."}
		}
		return nil, &httpError{403, "forbidden", "This operation is not allowed for the discovered service."}
	}
	return nil, &httpError{409, "stale", "The service is no longer present. Refresh the inventory."}
}

func serviceFingerprint(service model.Service) [32]byte {
	// Presentation-only descriptions and unrelated listeners must not invalidate
	// approvals. Identity, runtime state, and authorization changes must do so.
	actions := append([]string(nil), service.Actions...)
	sort.Strings(actions)
	value := struct {
		ID, Name, Manager, Scope, State, Substate, Enabled, WorkingDirectory, Path, ProtectionReason string
		PID                                                                                          int
		Actions                                                                                      []string
	}{service.ID, service.Name, service.Manager, service.Scope, service.State, service.Substate,
		service.Enabled, service.WorkingDirectory, service.Path, service.ProtectionReason, service.PID, actions}
	data, _ := json.Marshal(value)
	return sha256.Sum256(data)
}

func (s *server) previewAction(w http.ResponseWriter, r *http.Request, current *session) {
	var req model.ActionRequest
	if !decodeJSON(w, r, &req, 4096) {
		return
	}
	if err := validateAction(req); err != nil {
		writeError(w, err)
		return
	}
	service, err := s.actionable(r.Context(), req, false)
	if err != nil {
		writeError(w, err)
		return
	}
	token, err := randomToken()
	if err != nil {
		writeError(w, err)
		return
	}
	confirmation := req.Operation + " " + service.Name
	expires := time.Now().Add(2 * time.Minute)
	s.approvalMu.Lock()
	for key, value := range s.approvals {
		if !time.Now().Before(value.Expires) {
			delete(s.approvals, key)
		}
	}
	if len(s.approvals) >= 256 {
		s.approvalMu.Unlock()
		apiError(w, 429, "rate_limit", "Too many pending approvals. Wait for old previews to expire.")
		return
	}
	s.approvals[token] = actionApproval{current.Actor, req, serviceFingerprint(*service), confirmation, expires}
	s.approvalMu.Unlock()
	warnings := []string{"The service state is rechecked at apply time; an expired or changed preview cannot be applied."}
	if req.Operation == "stop" || req.Operation == "restart" {
		warnings = append(warnings, "This can interrupt the service and clients that depend on it.")
	}
	writeJSON(w, 200, model.Preview{
		Token: token, Summary: req.Operation + " " + service.Name + " (" + service.ID + ")",
		Confirmation: confirmation, Warnings: warnings, ExpiresAt: expires,
	})
}

func (s *server) applyAction(w http.ResponseWriter, r *http.Request, current *session) {
	var req model.ApplyRequest
	if !decodeJSON(w, r, &req, 4096) {
		return
	}
	if len(req.Token) != 43 {
		apiError(w, 400, "validation", "A lifecycle preview token is required.")
		return
	}
	s.approvalMu.Lock()
	approval, exists := s.approvals[req.Token]
	if exists && approval.Actor == current.Actor {
		delete(s.approvals, req.Token)
	}
	s.approvalMu.Unlock()
	if !exists || !time.Now().Before(approval.Expires) {
		apiError(w, 409, "stale", "The preview has expired or was already used. Request a new preview.")
		return
	}
	if approval.Actor != current.Actor {
		apiError(w, 403, "forbidden", "This preview belongs to another actor.")
		return
	}
	if !constantEqual(req.Confirmation, approval.Confirmation) {
		apiError(w, 400, "validation", "The confirmation does not match exactly. Request a new preview.")
		return
	}
	// Serial revalidation prevents two approvals from racing against the same
	// pre-change state. There is no queued background control operation.
	if !s.actionMu.TryLock() {
		apiError(w, 409, "stale", "Another lifecycle operation is in progress. Request a new preview afterward.")
		return
	}
	defer s.actionMu.Unlock()
	service, err := s.actionable(r.Context(), approval.Request, true)
	if err != nil {
		writeError(w, err)
		return
	}
	if !time.Now().Before(approval.Expires) || serviceFingerprint(*service) != approval.Fingerprint {
		apiError(w, 409, "stale", "The service state or its permissions changed. Request a new preview.")
		return
	}
	if r.Context().Err() != nil {
		writeError(w, r.Context().Err())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if userService(*service) {
		entry := model.AuditEntry{Actor: current.Actor, Operation: approval.Request.Operation, Target: approval.Request.ID,
			Detail: "Accepted; completion has not yet been recorded."}
		// Persist the intent before executing. If the process dies mid-command,
		// the audit is explicit about uncertainty rather than claiming failure.
		if err := s.audit.append(entry); err != nil {
			apiError(w, 503, "unavailable", "The local audit cannot be persisted; no action was invoked.")
			return
		}
		err = discovery.UserAction(ctx, approval.Request)
		entry.Success = err == nil
		if err == nil {
			entry.Detail = "Completed."
		} else {
			entry.Detail = "The user service manager could not confirm completion; inspect current state before retrying."
		}
		auditErr := s.audit.append(entry)
		s.afterChange(r.Context())
		if auditErr != nil {
			apiError(w, 500, "internal", "The action was invoked but its outcome could not be persisted. Inspect current state before retrying.")
			return
		}
		if err != nil {
			apiError(w, 503, "unavailable", "The user service manager could not confirm completion. Refresh to inspect current state.")
			return
		}
	} else {
		if !s.requireBroker(w) {
			return
		}
		err = s.broker.Action(ctx, approval.Request, current.Actor)
		s.afterChange(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
