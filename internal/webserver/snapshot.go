package webserver

import (
	"context"
	"errors"
	"time"

	"github.com/astoreyai/hostdesk/internal/model"
)

func (s *server) privilegedSnapshot(ctx context.Context) (model.PrivilegedSnapshot, error) {
	if s.broker == nil {
		s.setBrokerAvailable(false)
		return model.PrivilegedSnapshot{}, errors.New("privileged broker is not configured")
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	value, err := s.broker.Snapshot(callCtx)
	s.setBrokerAvailable(err == nil)
	return value, err
}

func (s *server) setBrokerAvailable(available bool) {
	s.cacheMu.Lock()
	s.brokerAvailable = available
	s.brokerChecked = time.Now()
	s.cacheMu.Unlock()
}

func (s *server) checkBroker(ctx context.Context) {
	if s.broker == nil {
		return
	}
	s.cacheMu.Lock()
	if time.Since(s.brokerChecked) < 3*time.Second {
		s.cacheMu.Unlock()
		return
	}
	if s.brokerChecking != nil {
		done := s.brokerChecking
		s.cacheMu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
		}
		return
	}
	done := make(chan struct{})
	s.brokerChecking = done
	s.cacheMu.Unlock()
	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	_, err := s.broker.Network(callCtx)
	cancel()
	s.cacheMu.Lock()
	s.brokerAvailable = err == nil
	s.brokerChecked = time.Now()
	s.brokerChecking = nil
	close(done)
	s.cacheMu.Unlock()
}

// Collection has a server-owned deadline, not the first HTTP caller's lifetime:
// disconnecting one browser cannot cancel the shared work for every other tab.
// Forced refreshes join existing collection instead of spawning command storms.
func (s *server) snapshot(ctx context.Context, force bool) (*model.Snapshot, error) {
	s.cacheMu.Lock()
	if !force && s.cached != nil && time.Since(s.cacheTime) < time.Duration(s.cfg.RefreshSeconds)*time.Second {
		result := s.cached
		s.cacheMu.Unlock()
		return result, nil
	}
	done := s.collecting
	if done == nil {
		if s.ctx.Err() != nil {
			s.cacheMu.Unlock()
			return nil, s.ctx.Err()
		}
		done = make(chan struct{})
		s.collecting = done
		epoch := s.cacheEpoch
		s.work.Add(1)
		go func() {
			defer s.work.Done()
			collectCtx, cancel := context.WithTimeout(s.ctx, 35*time.Second)
			value := s.collector.Collect(collectCtx)
			cancel()
			s.cacheMu.Lock()
			if !s.brokerAvailable {
				for i := range value.Services {
					if value.Services[i].Scope != "user" || value.Services[i].Manager != "systemd" {
						value.Services[i].Actions = []string{}
						if value.Services[i].ProtectionReason == "" {
							value.Services[i].ProtectionReason = "Privileged broker unavailable."
						}
					}
				}
			}
			if value.Sources == nil {
				value.Sources = []model.Source{}
			}
			if value.Services == nil {
				value.Services = []model.Service{}
			}
			if value.Listeners == nil {
				value.Listeners = []model.Listener{}
			}
			if value.Projects == nil {
				value.Projects = []model.Project{}
			}
			if value.Routes == nil {
				value.Routes = []model.Route{}
			}
			if value.Warnings == nil {
				value.Warnings = []string{}
			}
			s.cached = &value
			if epoch == s.cacheEpoch {
				s.cacheTime = time.Now()
			} else {
				s.cacheTime = time.Time{}
			}
			s.collecting = nil
			close(done)
			s.cacheMu.Unlock()
		}()
	}
	s.cacheMu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		s.cacheMu.Lock()
		result := s.cached
		s.cacheMu.Unlock()
		return result, nil
	}
}

func (s *server) afterChange(ctx context.Context) {
	// Drain any pre-action collection before forcing a post-action read. Merely
	// expiring the cache would let a concurrent in-flight old snapshot win.
	s.cacheMu.Lock()
	pending := s.collecting
	s.cacheEpoch++
	s.cacheTime = time.Time{}
	s.cacheMu.Unlock()
	if pending != nil {
		select {
		case <-pending:
		case <-ctx.Done():
			return
		}
	}
	s.cacheMu.Lock()
	s.cacheTime = time.Time{}
	s.cacheMu.Unlock()
	_, _ = s.snapshot(ctx, true)
}
