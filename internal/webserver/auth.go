package webserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"
)

const cookieName = "hostdesk_session"

type session struct {
	Actor   string
	CSRF    string
	Expires time.Time
	Digest  [32]byte
}

type rateBucket struct {
	Tokens  float64
	Updated time.Time
}

func constantEqual(a, b string) bool {
	aHash, bHash := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

// Fixed-capacity, idle-expiring buckets avoid unbounded memory from invented
// clients. Proxy sessions use authenticated identity, never forwarded IPs.
func (s *server) allowRate(key string, capacity, perMinute float64) bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	now := time.Now()
	for key, bucket := range s.rates {
		if now.Sub(bucket.Updated) > 10*time.Minute {
			delete(s.rates, key)
		}
	}
	bucket := s.rates[key]
	if bucket == nil {
		if len(s.rates) >= 1024 {
			return false
		}
		bucket = &rateBucket{Tokens: capacity, Updated: now}
		s.rates[key] = bucket
	}
	bucket.Tokens += now.Sub(bucket.Updated).Minutes() * perMinute
	if bucket.Tokens > capacity {
		bucket.Tokens = capacity
	}
	bucket.Updated = now
	if bucket.Tokens < 1 {
		return false
	}
	bucket.Tokens--
	return true
}

func (s *server) pruneSessions(now time.Time) {
	for key, value := range s.sessions {
		if !now.Before(value.Expires) {
			delete(s.sessions, key)
		}
	}
	for key, value := range s.proxySessions {
		if !now.Before(value.Expires) {
			delete(s.proxySessions, key)
		}
	}
}

func (s *server) authenticate(r *http.Request) (*session, error) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	now := time.Now()
	s.pruneSessions(now)
	// The external Host requirement prevents identity assertions on the direct
	// loopback origin. Trust is explicitly in the local proxy/host, not a header
	// signed by Tailscale; another local process can impersonate that proxy.
	identities := r.Header.Values("Tailscale-User-Login")
	if s.external != nil && r.Host == s.external.Host && loopbackPeer(r.RemoteAddr) && len(identities) == 1 && s.allowedUsers[identities[0]] {
		identity := identities[0]
		if existing := s.proxySessions[identity]; existing != nil {
			return existing, nil
		}
		if len(s.proxySessions) >= 256 {
			return nil, &httpError{503, "unavailable", "The proxy session limit has been reached."}
		}
		csrf, err := randomToken()
		if err != nil {
			return nil, err
		}
		created := &session{Actor: "tailscale:" + identity, CSRF: csrf, Expires: now.Add(sessionLifetime)}
		s.proxySessions[identity] = created
		return created, nil
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil || len(cookie.Value) != 43 {
		return nil, nil
	}
	digest := sha256.Sum256([]byte(cookie.Value))
	value := s.sessions[digest]
	if value == nil || subtle.ConstantTimeCompare(digest[:], value.Digest[:]) != 1 {
		return nil, nil
	}
	return value, nil
}

func (s *server) login(w http.ResponseWriter, r *http.Request, origin string) {
	if !s.allowRate("login", 5, 5) {
		w.Header().Set("Retry-After", "12")
		apiError(w, 429, "rate_limit", "Too many login attempts. Try again later.")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &req, 4096) {
		return
	}
	if !constantEqual(req.Token, s.ownerToken) {
		apiError(w, 401, "auth", "Invalid owner token.")
		return
	}
	value, err := randomToken()
	if err != nil {
		writeError(w, err)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		writeError(w, err)
		return
	}
	now := time.Now()
	digest := sha256.Sum256([]byte(value))
	created := &session{Actor: "owner", CSRF: csrf, Expires: now.Add(sessionLifetime), Digest: digest}
	s.authMu.Lock()
	s.pruneSessions(now)
	if len(s.sessions) >= 256 {
		s.authMu.Unlock()
		apiError(w, 429, "rate_limit", "The session limit has been reached. End an existing session or wait for expiry.")
		return
	}
	if old, err := r.Cookie(cookieName); err == nil {
		oldDigest := sha256.Sum256([]byte(old.Value))
		delete(s.sessions, oldDigest)
	}
	s.sessions[digest] = created
	s.authMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: strings.HasPrefix(origin, "https://"), SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionLifetime.Seconds()), Expires: created.Expires,
	})
	s.checkBroker(r.Context())
	s.sessionResponse(w, created, origin)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, origin string) {
	if !decodeJSON(w, r, &struct{}{}, 1024) {
		return
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		digest := sha256.Sum256([]byte(cookie.Value))
		s.authMu.Lock()
		delete(s.sessions, digest)
		s.authMu.Unlock()
	}
	// Do not revoke proxy identity: the next trusted request authenticates
	// independently of cookies, and its CSRF remains stable until expiry.
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", HttpOnly: true,
		Secure: strings.HasPrefix(origin, "https://"), SameSite: http.SameSiteStrictMode,
		MaxAge: -1, Expires: time.Unix(1, 0)})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *server) sessionResponse(w http.ResponseWriter, current *session, origin string) {
	s.cacheMu.Lock()
	available := s.brokerAvailable
	s.cacheMu.Unlock()
	writeJSON(w, 200, struct {
		Authenticated bool   `json:"authenticated"`
		Actor         string `json:"actor"`
		CSRF          string `json:"csrf"`
		Capabilities  struct {
			Broker bool `json:"broker"`
		} `json:"capabilities"`
		Origin string `json:"origin"`
	}{true, current.Actor, current.CSRF, struct {
		Broker bool `json:"broker"`
	}{available}, origin})
}
