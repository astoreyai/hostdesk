package webserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/astoreyai/hostdesk/internal/broker"
	"github.com/astoreyai/hostdesk/internal/model"
)

type httpError struct {
	status        int
	code, message string
}

func (e *httpError) Error() string { return e.message }

func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}{message, code})
}

func writeError(w http.ResponseWriter, err error) {
	var local *httpError
	if errors.As(err, &local) {
		apiError(w, local.status, local.code, local.message)
		return
	}
	var remote *broker.Error
	if errors.As(err, &remote) {
		switch remote.Status {
		case 400, 403, 409, 503:
			apiError(w, remote.Status, remote.Code, remote.Message)
			return
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		apiError(w, 503, "unavailable", "The operation was interrupted or exceeded its deadline. Refresh before retrying.")
		return
	}
	apiError(w, 500, "internal", "The operation could not be completed.")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any, limit int64) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || r.Header.Get("Content-Encoding") != "" {
		apiError(w, 400, "validation", "Send an uncompressed application/json object.")
		return false
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			apiError(w, 413, "validation", "Request body is too large.")
		} else {
			apiError(w, 400, "validation", "Unable to read the request body.")
		}
		return false
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		apiError(w, 400, "validation", "A JSON object is required.")
		return false
	}
	if err := validateJSON(json.NewDecoder(bytes.NewReader(trimmed)), 0); err != nil {
		apiError(w, 400, "validation", "JSON must be valid and contain no duplicate fields or excessive nesting.")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		apiError(w, 400, "validation", "JSON fields or values do not match this endpoint.")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		apiError(w, 400, "validation", "Only one JSON object is allowed.")
		return false
	}
	return true
}

func validateJSON(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || keys[key] {
				return errors.New("duplicate or invalid JSON key")
			}
			keys[key] = true
			if err := validateJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func (s *server) serveAPI(w http.ResponseWriter, r *http.Request, origin string) {
	var method string
	switch r.URL.Path {
	case "/api/session", "/api/snapshot", "/api/network", "/api/audit":
		method = http.MethodGet
	case "/api/login", "/api/logout", "/api/refresh", "/api/actions/preview", "/api/actions/apply", "/api/network/preview", "/api/network/apply", "/api/network/confirm", "/api/network/rollback":
		method = http.MethodPost
	default:
		apiError(w, 404, "not_found", "Not found.")
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		apiError(w, 405, "method", "Method not allowed.")
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "validation", "This endpoint does not accept URL parameters.")
		return
	}
	if r.Method == http.MethodPost && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != origin) {
		apiError(w, 403, "forbidden", "A matching Origin header is required.")
		return
	}
	if r.URL.Path == "/api/login" {
		s.login(w, r, origin)
		return
	}
	current, err := s.authenticate(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if current == nil {
		apiError(w, 401, "auth", "Authentication is required.")
		return
	}
	if !s.allowRate("api:"+current.Actor, 120, 120) {
		w.Header().Set("Retry-After", "1")
		apiError(w, 429, "rate_limit", "Too many requests. Try again shortly.")
		return
	}
	if r.Method == http.MethodPost {
		if len(r.Header.Values("X-CSRF-Token")) != 1 || !constantEqual(r.Header.Get("X-CSRF-Token"), current.CSRF) {
			apiError(w, 403, "forbidden", "A valid session CSRF token is required.")
			return
		}
		if !s.allowRate("mutation:"+current.Actor, 12, 30) {
			w.Header().Set("Retry-After", "2")
			apiError(w, 429, "rate_limit", "Too many changes. Try again shortly.")
			return
		}
	}
	switch r.URL.Path {
	case "/api/session":
		s.checkBroker(r.Context())
		s.sessionResponse(w, current, origin)
	case "/api/logout":
		s.logout(w, r, origin)
	case "/api/snapshot", "/api/refresh":
		force := r.URL.Path == "/api/refresh"
		if force && !decodeJSON(w, r, &struct{}{}, 1024) {
			return
		}
		value, err := s.snapshot(r.Context(), force)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, 200, value)
	case "/api/actions/preview":
		s.previewAction(w, r, current)
	case "/api/actions/apply":
		s.applyAction(w, r, current)
	case "/api/network":
		s.getNetwork(w, r)
	case "/api/network/preview":
		s.previewNetwork(w, r, current)
	case "/api/network/apply":
		s.applyNetwork(w, r, current)
	case "/api/network/confirm", "/api/network/rollback":
		s.finishNetwork(w, r, current)
	case "/api/audit":
		s.getAudit(w, r)
	}
}

func unavailableNetwork(message string) model.NetworkState {
	return model.NetworkState{Available: false, Error: message,
		Policy: model.NetworkPolicy{Interfaces: []model.InterfacePolicy{}}, ProtectedTCPPorts: []int{}}
}

func (s *server) getNetwork(w http.ResponseWriter, r *http.Request) {
	if s.broker == nil {
		writeJSON(w, 200, unavailableNetwork("The privileged broker is not configured."))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	value, err := s.broker.Network(ctx)
	s.setBrokerAvailable(err == nil)
	if err != nil {
		writeJSON(w, 200, unavailableNetwork("The privileged broker is unavailable; network controls are disabled."))
		return
	}
	writeJSON(w, 200, value)
}

func (s *server) requireBroker(w http.ResponseWriter) bool {
	if s.broker != nil {
		return true
	}
	apiError(w, 503, "unavailable", "This operation requires the privileged broker.")
	return false
}

func (s *server) previewNetwork(w http.ResponseWriter, r *http.Request, current *session) {
	var req model.PolicyRequest
	if !decodeJSON(w, r, &req, 64<<10) || !s.requireBroker(w) {
		return
	}
	if req.Policy.Interfaces == nil {
		apiError(w, 400, "validation", "An explicit policy.interfaces array is required; use [] only to intentionally remove managed interface rules.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	value, err := s.broker.PreviewPolicy(ctx, req, current.Actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, 200, value)
}

func (s *server) applyNetwork(w http.ResponseWriter, r *http.Request, current *session) {
	var req model.ApplyRequest
	if !decodeJSON(w, r, &req, 4096) || !s.requireBroker(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	value, err := s.broker.ApplyPolicy(ctx, req, current.Actor)
	// A transport interruption can follow a successful mutation. Invalidate
	// inventory even on errors, never imply that the policy remained unchanged.
	s.afterChange(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, 200, value)
}

func (s *server) finishNetwork(w http.ResponseWriter, r *http.Request, current *session) {
	var req struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &req, 4096) || !s.requireBroker(w) {
		return
	}
	if req.Token == "" || len(req.Token) > 256 {
		apiError(w, 400, "validation", "A valid pending policy token is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var value model.NetworkState
	var err error
	if r.URL.Path == "/api/network/confirm" {
		value, err = s.broker.ConfirmPolicy(ctx, req.Token, current.Actor)
	} else {
		value, err = s.broker.RollbackPolicy(ctx, req.Token, current.Actor)
	}
	s.afterChange(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, 200, value)
}
