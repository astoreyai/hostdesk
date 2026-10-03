package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"syscall"
	"time"

	"github.com/astoreyai/hostdesk/internal/model"
)

type Client struct{ Socket string }

func (c *Client) call(ctx context.Context, method, path string, payload, result any) error {
	if c.Socket == "" || !filepath.IsAbs(c.Socket) {
		return unavailable("root broker is not configured")
	}
	var input io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return invalid("broker request cannot be encoded")
		}
		if len(data) > 1<<20 {
			return invalid("broker request is too large")
		}
		input = bytes.NewReader(data)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", c.Socket)
			if err != nil {
				return nil, err
			}
			unix, ok := connection.(*net.UnixConn)
			if !ok {
				connection.Close()
				return nil, unavailable("broker transport is not a Unix socket")
			}
			raw, err := unix.SyscallConn()
			if err != nil {
				connection.Close()
				return nil, err
			}
			var credential *syscall.Ucred
			var credentialErr error
			if err := raw.Control(func(fd uintptr) {
				credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			}); err != nil || credentialErr != nil || credential == nil || credential.Uid != 0 {
				connection.Close()
				return nil, unavailable("broker peer is not root")
			}
			return connection, nil
		},
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  80 * time.Second,
		MaxResponseHeaderBytes: 8192,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 85 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, method, "http://broker"+path, input)
	if err != nil {
		return invalid("invalid broker request")
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return unavailable("root broker is unavailable; its configured Unix socket could not complete the request")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return unavailable("root broker returned an unreadable or oversized response")
	}
	if response.StatusCode != http.StatusOK {
		var apiError Error
		if err := json.Unmarshal(data, &apiError); err != nil || apiError.Message == "" || apiError.Code == "" {
			return unavailable("root broker returned an invalid error response")
		}
		apiError.Status = response.StatusCode
		return &apiError
	}
	if err := json.Unmarshal(data, result); err != nil {
		return unavailable("root broker returned invalid JSON")
	}
	return nil
}

func (c *Client) Snapshot(ctx context.Context) (model.PrivilegedSnapshot, error) {
	var result model.PrivilegedSnapshot
	err := c.call(ctx, http.MethodGet, "/snapshot", nil, &result)
	return result, err
}
func (c *Client) Network(ctx context.Context) (model.NetworkState, error) {
	var result model.NetworkState
	err := c.call(ctx, http.MethodGet, "/network", nil, &result)
	return result, err
}
func (c *Client) Action(ctx context.Context, req model.ActionRequest, actor string) error {
	var result struct {
		OK bool `json:"ok"`
	}
	if err := c.call(ctx, http.MethodPost, "/action", actionEnvelope{Actor: actor, Request: req}, &result); err != nil {
		return err
	}
	if !result.OK {
		return unavailable("broker did not acknowledge the action")
	}
	return nil
}
func (c *Client) PreviewPolicy(ctx context.Context, req model.PolicyRequest, actor string) (model.Preview, error) {
	var result model.Preview
	err := c.call(ctx, http.MethodPost, "/network/preview", policyEnvelope{Actor: actor, Request: req}, &result)
	return result, err
}
func (c *Client) ApplyPolicy(ctx context.Context, req model.ApplyRequest, actor string) (model.NetworkState, error) {
	var result model.NetworkState
	err := c.call(ctx, http.MethodPost, "/network/apply", applyEnvelope{Actor: actor, Request: req}, &result)
	return result, err
}
func (c *Client) ConfirmPolicy(ctx context.Context, token string, actor string) (model.NetworkState, error) {
	var result model.NetworkState
	err := c.call(ctx, http.MethodPost, "/network/confirm", tokenEnvelope{Actor: actor, Token: token}, &result)
	return result, err
}
func (c *Client) RollbackPolicy(ctx context.Context, token string, actor string) (model.NetworkState, error) {
	var result model.NetworkState
	err := c.call(ctx, http.MethodPost, "/network/rollback", tokenEnvelope{Actor: actor, Token: token}, &result)
	return result, err
}
func (c *Client) Audit(ctx context.Context) ([]model.AuditEntry, error) {
	result := []model.AuditEntry{}
	err := c.call(ctx, http.MethodGet, "/audit", nil, &result)
	return result, err
}
