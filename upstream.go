package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// lapi is one upstream Local API. Sessions hold the per-agent logins to it.
type lapi struct {
	name   string
	base   string // no trailing slash
	client *http.Client
}

func newLAPI(cfg UpstreamConfig) (*lapi, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates found", cfg.CAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &lapi{
		name:   cfg.Name,
		base:   strings.TrimRight(cfg.URL, "/"),
		client: &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}, nil
}

// session is one agent's login to one LAPI. Alerts sent through it are
// recorded by the LAPI under the agent's machine ID.
type session struct {
	lapi     *lapi
	login    string
	password string
	agent    *agentState

	mu     sync.Mutex
	token  string
	expire time.Time
	// scenarios/UA the token was issued with; a change forces a new login so
	// the LAPI (and CAPI, through it) sees what the agent runs.
	loginGen uint64
}

// errRejected is a 4xx other than 401/403: retrying the same body won't help.
type errRejected struct {
	status int
	body   string
}

func (e *errRejected) Error() string {
	return fmt.Sprintf("rejected with HTTP %d: %s", e.status, e.body)
}

func (s *session) loginLocked(ctx context.Context) error {
	scenarios, ua, gen := s.agent.loginInfo()
	body, _ := json.Marshal(map[string]any{
		"machine_id": s.login,
		"password":   s.password,
		"scenarios":  scenarios,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.lapi.base+"/v1/watchers/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// The LAPI refuses a login whose User-Agent is not exactly "name/version",
	// and stores the version part as the machine's version.
	req.Header.Set("User-Agent", ua)
	resp, err := s.lapi.client.Do(req)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login as %s: HTTP %d: %s", s.login, resp.StatusCode, snippet(rb))
	}
	var lr struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	if err := json.Unmarshal(rb, &lr); err != nil || lr.Token == "" {
		return fmt.Errorf("login as %s: unexpected response: %s", s.login, snippet(rb))
	}
	exp, err := time.Parse(time.RFC3339, lr.Expire)
	if err != nil {
		return fmt.Errorf("login as %s: bad expire %q: %w", s.login, lr.Expire, err)
	}
	s.token, s.expire, s.loginGen = lr.Token, exp, gen
	return nil
}

func (s *session) currentToken(ctx context.Context, force bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if force || s.token == "" || time.Until(s.expire) < time.Minute || s.loginGen != s.agent.generation() {
		s.token = ""
		if err := s.loginLocked(ctx); err != nil {
			return "", err
		}
	}
	return s.token, nil
}

// do sends an authenticated request, logging in again once on 401/403.
// header carries Content-Type/Content-Encoding of a forwarded body.
func (s *session) do(ctx context.Context, method, path string, body []byte, header http.Header) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		tok, err := s.currentToken(ctx, attempt > 0)
		if err != nil {
			return nil, err
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, s.lapi.base+path, rd)
		if err != nil {
			return nil, err
		}
		for k, v := range header {
			req.Header[k] = v
		}
		_, ua, _ := s.agent.loginInfo()
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := s.lapi.client.Do(req)
		if err != nil {
			return nil, err
		}
		if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && attempt == 0 {
			drain(resp)
			continue
		}
		return resp, nil
	}
}

// postAlerts delivers one queued batch. A nil error means the LAPI stored it.
func (s *session) postAlerts(ctx context.Context, body []byte, gzipped bool) error {
	h := http.Header{"Content-Type": {"application/json"}}
	if gzipped {
		h.Set("Content-Encoding", "gzip")
	}
	resp, err := s.do(ctx, http.MethodPost, "/v1/alerts", body, h)
	if err != nil {
		return err
	}
	defer drain(resp)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500 &&
		resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden &&
		resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &errRejected{resp.StatusCode, snippet(rb)}
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(rb))
}

func (s *session) heartbeat(ctx context.Context) error {
	resp, err := s.do(ctx, http.MethodGet, "/v1/heartbeat", nil, nil)
	if err != nil {
		return err
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat: HTTP %d", resp.StatusCode)
	}
	return nil
}

func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func isRejected(err error) bool {
	var r *errRejected
	return errors.As(err, &r)
}
