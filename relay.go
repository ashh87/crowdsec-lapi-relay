package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxBodySize        = 32 << 20 // as received, possibly gzipped
	maxDecompressedHdr = 64 << 20
	agentSeenTimeout   = 5 * time.Minute
)

// agentState is what the relay knows about one configured log processor.
type agentState struct {
	cfg     AgentConfig
	pwHash  [32]byte
	queues  []*queue // one per LAPI, config order
	session map[string]*session

	mu        sync.Mutex
	scenarios []string
	userAgent string
	gen       uint64
	lastSeen  time.Time
}

func (a *agentState) loginInfo() ([]string, string, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ua := a.userAgent
	if ua == "" {
		ua = "lapi-relay/" + version
	}
	return a.scenarios, ua, a.gen
}

func (a *agentState) generation() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gen
}

func (a *agentState) seen() {
	a.mu.Lock()
	a.lastSeen = time.Now()
	a.mu.Unlock()
}

func (a *agentState) active() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.lastSeen) < agentSeenTimeout
}

// updateLogin records the agent's scenarios and User-Agent; if either changed,
// sessions log in again on next use so each LAPI stores the new values.
func (a *agentState) updateLogin(scenarios []string, ua string) {
	scenarios = slices.Clone(scenarios)
	sort.Strings(scenarios)
	// The LAPI rejects a User-Agent that isn't exactly one "name/version".
	if strings.Count(ua, "/") != 1 {
		ua = ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastSeen = time.Now()
	if !slices.Equal(scenarios, a.scenarios) || ua != a.userAgent {
		a.scenarios, a.userAgent = scenarios, ua
		a.gen++
	}
}

type relay struct {
	cfg    *Config
	spool  *spool
	lapis  []*lapi
	agents map[string]*agentState
	start  time.Time

	tokMu  sync.Mutex
	tokens map[string]tokenInfo

	received atomic.Uint64
	badLogin atomic.Uint64

	orphanBatches int // in queues not in the config, as found at startup
}

type tokenInfo struct {
	agent  *agentState
	expire time.Time
}

func newRelay(cfg *Config) (*relay, error) {
	sp, err := newSpool(cfg.QueueDir, int64(cfg.MaxQueueBytes))
	if err != nil {
		return nil, err
	}
	r := &relay{cfg: cfg, spool: sp, agents: map[string]*agentState{}, tokens: map[string]tokenInfo{}, start: time.Now()}
	for _, uc := range cfg.LAPIs {
		l, err := newLAPI(uc)
		if err != nil {
			return nil, fmt.Errorf("lapi %s: %w", uc.Name, err)
		}
		r.lapis = append(r.lapis, l)
	}
	for _, ac := range cfg.Agents {
		a := &agentState{cfg: ac, pwHash: sha256.Sum256([]byte(ac.Password)), session: map[string]*session{}}
		for _, l := range r.lapis {
			login, pw := ac.credentialsFor(l.name)
			s := &session{lapi: l, login: login, password: pw, agent: a}
			a.session[l.name] = s
			q, err := newQueue(cfg.QueueDir, s, cfg.MaxQueueFiles, time.Duration(cfg.MaxQueueAge))
			if err != nil {
				return nil, err
			}
			a.queues = append(a.queues, q)
		}
		r.agents[ac.Login] = a
	}
	sp.queues = r.allQueues()
	sp.enforceSize() // the limit may have been lowered since the last run

	inUse := map[string]bool{}
	for _, q := range sp.queues {
		inUse[q.dir] = true
	}
	orphans, err := checkOrphanQueues(cfg.QueueDir, inUse, cfg.PruneOrphanQueues)
	if err != nil {
		return nil, fmt.Errorf("checking for queues not in the config: %w", err)
	}
	for _, o := range orphans {
		r.orphanBatches += o.batches
	}
	return r, nil
}

func (r *relay) allQueues() []*queue {
	var qs []*queue
	for _, l := range r.cfg.Agents {
		qs = append(qs, r.agents[l.Login].queues...)
	}
	return qs
}

func (r *relay) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/watchers/login", r.handleLogin)
	mux.HandleFunc("POST /v1/alerts", r.auth(r.handleAlerts))
	mux.HandleFunc("GET /v1/heartbeat", r.auth(r.handleHeartbeat))
	mux.HandleFunc("POST /v1/usage-metrics", r.auth(r.handleUsageMetrics))
	// Read-only, answered by the first LAPI that responds. AppSec uses these.
	mux.HandleFunc("GET /v1/allowlists", r.auth(r.handlePassthrough))
	mux.HandleFunc("GET /v1/allowlists/{rest...}", r.auth(r.handlePassthrough))
	mux.HandleFunc("HEAD /v1/allowlists/check/{rest...}", r.auth(r.handlePassthrough))
	mux.HandleFunc("POST /v1/allowlists/check", r.auth(r.handlePassthrough))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"up"}`)
	})
	mux.HandleFunc("GET /metrics", r.handleMetrics)
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		slog.Debug("unsupported endpoint", "method", req.Method, "path", req.URL.Path)
		writeJSON(w, http.StatusNotImplemented, map[string]string{"message": "not supported by lapi-relay"})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (r *relay) handleLogin(w http.ResponseWriter, req *http.Request) {
	var in struct {
		MachineID string   `json:"machine_id"`
		Password  string   `json:"password"`
		Scenarios []string `json:"scenarios"`
	}
	body, err := readBody(req)
	if err == nil {
		err = json.Unmarshal(body, &in)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 400, "message": "bad request"})
		return
	}
	a := r.agents[in.MachineID]
	h := sha256.Sum256([]byte(in.Password))
	var want [32]byte
	if a != nil {
		want = a.pwHash
	}
	// Compare even for unknown logins so timing doesn't reveal which exist.
	if subtle.ConstantTimeCompare(h[:], want[:]) != 1 || a == nil {
		r.badLogin.Add(1)
		slog.Warn("failed agent login", "machine_id", in.MachineID, "remote", req.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 401, "message": "incorrect Username or Password"})
		return
	}
	a.updateLogin(in.Scenarios, req.UserAgent())

	var raw [32]byte
	rand.Read(raw[:])
	tok := hex.EncodeToString(raw[:])
	exp := time.Now().Add(time.Duration(r.cfg.TokenTTL)).UTC()
	r.tokMu.Lock()
	now := time.Now()
	for k, v := range r.tokens {
		if now.After(v.expire) {
			delete(r.tokens, k)
		}
	}
	r.tokens[tok] = tokenInfo{agent: a, expire: exp}
	r.tokMu.Unlock()

	slog.Info("agent logged in", "machine_id", in.MachineID, "scenarios", len(in.Scenarios), "user_agent", req.UserAgent())
	writeJSON(w, http.StatusOK, map[string]any{"code": 200, "expire": exp.Format(time.RFC3339), "token": tok})
}

type agentHandler func(http.ResponseWriter, *http.Request, *agentState)

func (r *relay) auth(next agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		tok, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
		r.tokMu.Lock()
		ti, found := r.tokens[tok]
		r.tokMu.Unlock()
		if !ok || !found || time.Now().After(ti.expire) {
			// The CrowdSec client logs in again on 401.
			writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 401, "message": "Token is expired"})
			return
		}
		ti.agent.seen()
		next(w, req, ti.agent)
	}
}

func readBody(req *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(nil, req.Body, maxBodySize))
}

func (r *relay) handleAlerts(w http.ResponseWriter, req *http.Request, a *agentState) {
	body, err := readBody(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	var gz bool
	switch enc := strings.ToLower(req.Header.Get("Content-Encoding")); enc {
	case "", "identity":
	case "gzip":
		gz = true
	default:
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"message": "unsupported Content-Encoding " + enc})
		return
	}
	n, err := countAlerts(body, gz)
	if err != nil {
		// Never queue what no LAPI will accept: it would block the queue head.
		slog.Warn("rejecting malformed alert batch", "agent", a.cfg.Login, "err", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	if err := r.spool.enqueue(body, gz, a.queues); err != nil {
		slog.Error("queueing alert batch failed, agent will retry", "agent", a.cfg.Login, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "relay queue unavailable"})
		return
	}
	r.received.Add(1)
	slog.Debug("queued alert batch", "agent", a.cfg.Login, "alerts", n)
	// The LAPI answers with the new alert IDs. These are per LAPI and the
	// agent ignores them, so return none rather than invent some.
	writeJSON(w, http.StatusCreated, []string{})
}

// countAlerts checks the body is a JSON array of objects.
func countAlerts(body []byte, gz bool) (int, error) {
	var rd io.Reader = bytes.NewReader(body)
	if gz {
		zr, err := gzip.NewReader(rd)
		if err != nil {
			return 0, fmt.Errorf("bad gzip body: %w", err)
		}
		rd = io.LimitReader(zr, maxDecompressedHdr)
	}
	var alerts []map[string]json.RawMessage
	if err := json.NewDecoder(rd).Decode(&alerts); err != nil {
		return 0, fmt.Errorf("body is not a JSON array of alerts: %w", err)
	}
	if len(alerts) == 0 {
		return 0, errors.New("empty alert batch")
	}
	return len(alerts), nil
}

// The relay sends its own heartbeats per agent (see heartbeatLoop), so the
// agent's heartbeat only marks it alive.
func (r *relay) handleHeartbeat(w http.ResponseWriter, _ *http.Request, _ *agentState) {
	w.WriteHeader(http.StatusOK)
}

// Usage metrics are best effort and not queued: they are periodic snapshots.
func (r *relay) handleUsageMetrics(w http.ResponseWriter, req *http.Request, a *agentState) {
	body, err := readBody(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if ce := req.Header.Get("Content-Encoding"); ce != "" {
		h.Set("Content-Encoding", ce)
	}
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, l := range r.lapis {
		s := a.session[l.name]
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := s.do(ctx, http.MethodPost, "/v1/usage-metrics", body, h)
			if err != nil {
				slog.Debug("usage metrics not forwarded", "lapi", l.name, "agent", a.cfg.Login, "err", err)
				return
			}
			if resp.StatusCode >= 300 {
				rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				slog.Warn("usage metrics refused", "lapi", l.name, "agent", a.cfg.Login, "status", resp.StatusCode, "body", snippet(rb))
			}
			drain(resp)
		}()
	}
	wg.Wait()
	w.WriteHeader(http.StatusCreated)
}

func (r *relay) handlePassthrough(w http.ResponseWriter, req *http.Request, a *agentState) {
	var body []byte
	if req.Method == http.MethodPost {
		var err error
		if body, err = readBody(req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
	}
	h := http.Header{}
	for _, k := range []string{"Content-Type", "Content-Encoding", "Accept"} {
		if v := req.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	for _, l := range r.lapis {
		resp, err := a.session[l.name].do(ctx, req.Method, req.URL.RequestURI(), body, h)
		if err != nil {
			slog.Debug("passthrough failed, trying next LAPI", "lapi", l.name, "path", req.URL.Path, "err", err)
			continue
		}
		if resp.StatusCode >= 500 {
			drain(resp)
			continue
		}
		for _, k := range []string{"Content-Type", "Content-Encoding"} {
			if v := resp.Header.Get(k); v != "" {
				w.Header().Set(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		resp.Body.Close()
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]string{"message": "no LAPI reachable"})
}

// heartbeatLoop keeps each LAPI's view of an agent current: while the agent
// talks to the relay, the relay heartbeats every LAPI as that agent. A good
// heartbeat also wakes a queue that is backing off, so replay starts promptly.
func (r *relay) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		r.heartbeatRound(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *relay) heartbeatRound(ctx context.Context) {
	for _, ac := range r.cfg.Agents {
		a := r.agents[ac.Login]
		if !a.active() {
			continue
		}
		for _, q := range a.queues {
			hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := q.sess.heartbeat(hctx)
			cancel()
			switch {
			case err == nil && q.depth.Load() > 0:
				q.signalRecovered()
			case err == nil:
				q.setUp(true)
			case ctx.Err() == nil:
				q.log.Debug("heartbeat failed", "err", err)
				q.setUp(false)
			}
		}
	}
}

// depthLogLoop logs non-empty queues once a minute.
func (r *relay) depthLogLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, q := range r.allQueues() {
			if d := q.depth.Load(); d > 0 {
				q.log.Info("queue depth", "depth", d, "lapi_up", q.up.Load())
			}
		}
	}
}

func (r *relay) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	qs := r.allQueues()
	metric := func(name, typ, help string, each func(q *queue)) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		for _, q := range qs {
			each(q)
		}
	}
	lbl := func(q *queue) string {
		return fmt.Sprintf(`lapi=%q,agent=%q`, q.sess.lapi.name, q.sess.agent.cfg.Login)
	}
	metric("lapi_relay_queue_depth", "gauge", "Alert batches waiting for delivery.", func(q *queue) {
		fmt.Fprintf(&b, "lapi_relay_queue_depth{%s} %d\n", lbl(q), q.depth.Load())
	})
	metric("lapi_relay_queue_bytes", "gauge", "Size of the alert batches waiting for delivery.", func(q *queue) {
		fmt.Fprintf(&b, "lapi_relay_queue_bytes{%s} %d\n", lbl(q), q.bytes.Load())
	})
	metric("lapi_relay_lapi_up", "gauge", "1 if the last delivery or heartbeat to this LAPI succeeded.", func(q *queue) {
		v := 0
		if q.up.Load() {
			v = 1
		}
		fmt.Fprintf(&b, "lapi_relay_lapi_up{%s} %d\n", lbl(q), v)
	})
	metric("lapi_relay_delivered_total", "counter", "Alert batches delivered.", func(q *queue) {
		fmt.Fprintf(&b, "lapi_relay_delivered_total{%s} %d\n", lbl(q), q.delivered.Load())
	})
	metric("lapi_relay_dropped_total", "counter", "Alert batches dropped (overflow of max_queue_files or max_queue_bytes, expired, rejected).", func(q *queue) {
		d := q.droppedCounts()
		for _, reason := range []string{"expired", "overflow", "rejected"} {
			fmt.Fprintf(&b, "lapi_relay_dropped_total{%s,reason=%q} %d\n", lbl(q), reason, d[reason])
		}
	})
	fmt.Fprintf(&b, "# HELP lapi_relay_received_total Alert batches accepted from agents.\n# TYPE lapi_relay_received_total counter\nlapi_relay_received_total %d\n", r.received.Load())
	fmt.Fprintf(&b, "# HELP lapi_relay_orphan_queue_batches Batches found at startup in queues that are not in the config.\n# TYPE lapi_relay_orphan_queue_batches gauge\nlapi_relay_orphan_queue_batches %d\n", r.orphanBatches)
	fmt.Fprintf(&b, "# HELP lapi_relay_failed_logins_total Rejected agent logins.\n# TYPE lapi_relay_failed_logins_total counter\nlapi_relay_failed_logins_total %d\n", r.badLogin.Load())
	io.WriteString(w, b.String())
}
