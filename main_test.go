package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// mockLAPI mimics the parts of the CrowdSec LAPI the relay uses, including
// its refusal of logins whose User-Agent is not "name/version".
type mockLAPI struct {
	srv   *httptest.Server
	creds map[string]string // machine -> password

	mu         sync.Mutex
	down       bool
	rejectNext int // answer 400 to this many alert posts
	tokens     map[string]string
	alerts     []postedAlert
	logins     []loginSeen
	heartbeats map[string]int
	n          int
}

type postedAlert struct {
	machine  string
	gzipped  bool
	scenario string
}

type loginSeen struct {
	machine   string
	ua        string
	scenarios []string
}

func newMockLAPI(t *testing.T, creds map[string]string) *mockLAPI {
	m := &mockLAPI{creds: creds, tokens: map[string]string{}, heartbeats: map[string]int{}}
	m.srv = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockLAPI) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if r.URL.Path == "/v1/watchers/login" {
		var in struct {
			MachineID string   `json:"machine_id"`
			Password  string   `json:"password"`
			Scenarios []string `json:"scenarios"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if pw, ok := m.creds[in.MachineID]; !ok || pw != in.Password || strings.Count(r.UserAgent(), "/") != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		m.n++
		tok := fmt.Sprintf("tok-%s-%d", in.MachineID, m.n)
		m.tokens[tok] = in.MachineID
		m.logins = append(m.logins, loginSeen{in.MachineID, r.UserAgent(), in.Scenarios})
		fmt.Fprintf(w, `{"code":200,"expire":%q,"token":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), tok)
		return
	}
	machine, ok := m.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/v1/alerts":
		var rd io.Reader = r.Body
		gz := r.Header.Get("Content-Encoding") == "gzip"
		if gz {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			rd = zr
		}
		var alerts []struct {
			Scenario string `json:"scenario"`
		}
		if err := json.NewDecoder(rd).Decode(&alerts); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if m.rejectNext > 0 {
			m.rejectNext--
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		for _, a := range alerts {
			m.alerts = append(m.alerts, postedAlert{machine, gz, a.Scenario})
		}
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `["1"]`)
	case "/v1/heartbeat":
		m.heartbeats[machine]++
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *mockLAPI) setDown(d bool) {
	m.mu.Lock()
	m.down = d
	m.mu.Unlock()
}

// expireTokens makes every issued token invalid, like a LAPI restart with a
// new JWT secret.
func (m *mockLAPI) expireTokens() {
	m.mu.Lock()
	m.tokens = map[string]string{}
	m.mu.Unlock()
}

func (m *mockLAPI) received() []postedAlert {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]postedAlert(nil), m.alerts...)
}

type testRelay struct {
	url    string
	r      *relay
	cancel context.CancelFunc
	done   chan error
}

func testConfig(dir string, lapis ...*mockLAPI) *Config {
	cfg := &Config{
		QueueDir:      dir,
		ShutdownGrace: Duration(time.Second),
		Agents: []AgentConfig{
			{Login: "agent-a", Password: "pw-a"},
			{Login: "agent-b", Password: "pw-b"},
		},
	}
	for i, l := range lapis {
		cfg.LAPIs = append(cfg.LAPIs, UpstreamConfig{Name: fmt.Sprintf("lapi%d", i+1), URL: l.srv.URL + "/"})
	}
	return cfg
}

func startRelay(t *testing.T, cfg *Config) *testRelay {
	t.Helper()
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	return startValidated(t, cfg)
}

// startValidated skips validate, for limits too small to be allowed in a config.
func startValidated(t *testing.T, cfg *Config) *testRelay {
	t.Helper()
	r, err := newRelay(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tr := &testRelay{url: "http://" + ln.Addr().String(), r: r, cancel: cancel, done: make(chan error, 1)}
	go func() { tr.done <- serve(ctx, r, ln) }()
	t.Cleanup(tr.stop)
	return tr
}

func (tr *testRelay) stop() {
	if tr.cancel == nil {
		return
	}
	tr.cancel()
	<-tr.done
	tr.cancel = nil
}

func (tr *testRelay) login(t *testing.T, machine, pw string, scenarios ...string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"machine_id": machine, "password": pw, "scenarios": scenarios})
	req, _ := http.NewRequest(http.MethodPost, tr.url+"/v1/watchers/login", bytes.NewReader(body))
	req.Header.Set("User-Agent", "crowdsec/v1.7.0-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	if _, err := time.Parse(time.RFC3339, out.Expire); err != nil {
		t.Fatalf("expire %q is not RFC3339 (the CrowdSec client requires it)", out.Expire)
	}
	return out.Token
}

func alertBody(scenarios ...string) []byte {
	var alerts []map[string]any
	for _, s := range scenarios {
		alerts = append(alerts, map[string]any{"scenario": s, "events": []any{}})
	}
	b, _ := json.Marshal(alerts)
	return b
}

func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func (tr *testRelay) post(t *testing.T, token string, body []byte, gz bool) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, tr.url+"/v1/alerts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

var bothAgents = map[string]string{"agent-a": "pw-a", "agent-b": "pw-b"}

func TestFanOutKeepsAgentIdentity(t *testing.T) {
	l1, l2 := newMockLAPI(t, bothAgents), newMockLAPI(t, bothAgents)
	tr := startRelay(t, testConfig(t.TempDir(), l1, l2))

	ta := tr.login(t, "agent-a", "pw-a", "crowdsecurity/ssh-bf")
	tb := tr.login(t, "agent-b", "pw-b")
	if ta == "" || tb == "" {
		t.Fatal("agent login failed")
	}
	if got := tr.post(t, ta, alertBody("ssh-bf"), false); got != http.StatusCreated {
		t.Fatalf("post: HTTP %d", got)
	}
	// The CrowdSec client gzips bodies over 5KB; they must reach the LAPI as sent.
	if got := tr.post(t, tb, gzipped(alertBody("http-probing")), true); got != http.StatusCreated {
		t.Fatalf("gzip post: HTTP %d", got)
	}

	want := map[postedAlert]bool{{"agent-a", false, "ssh-bf"}: true, {"agent-b", true, "http-probing"}: true}
	for i, l := range []*mockLAPI{l1, l2} {
		eventually(t, fmt.Sprintf("lapi%d delivery", i+1), func() bool { return len(l.received()) == 2 })
		for _, a := range l.received() {
			if !want[a] {
				t.Errorf("lapi%d got %+v, want one of %v", i+1, a, want)
			}
		}
	}
	l1.mu.Lock()
	defer l1.mu.Unlock()
	for _, lg := range l1.logins {
		if lg.machine == "agent-a" && (lg.ua != "crowdsec/v1.7.0-test" || len(lg.scenarios) != 1) {
			t.Errorf("upstream login for agent-a = %+v, want the agent's User-Agent and scenarios", lg)
		}
	}
}

func TestReplayAfterOutage(t *testing.T) {
	l1, l2 := newMockLAPI(t, bothAgents), newMockLAPI(t, bothAgents)
	tr := startRelay(t, testConfig(t.TempDir(), l1, l2))
	tok := tr.login(t, "agent-a", "pw-a")

	l2.setDown(true)
	for _, s := range []string{"one", "two", "three"} {
		if got := tr.post(t, tok, alertBody(s), false); got != http.StatusCreated {
			t.Fatalf("post while one LAPI down: HTTP %d", got)
		}
	}
	eventually(t, "lapi1 delivery", func() bool { return len(l1.received()) == 3 })
	if n := len(l2.received()); n != 0 {
		t.Fatalf("lapi2 is down but received %d alerts", n)
	}

	l2.setDown(false)
	tr.r.agents["agent-a"].queues[1].signalRecovered()
	eventually(t, "lapi2 replay", func() bool { return len(l2.received()) == 3 })
	got := l2.received()
	for i, s := range []string{"one", "two", "three"} {
		if got[i].scenario != s {
			t.Errorf("replay order: got %q at %d, want %q", got[i].scenario, i, s)
		}
	}
	if n := len(l1.received()); n != 3 {
		t.Errorf("lapi1 got %d alerts after replay, want 3 (no duplicates)", n)
	}
}

func TestQueueSurvivesRestart(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	dir := t.TempDir()
	l1.setDown(true)
	tr := startRelay(t, testConfig(dir, l1))
	if got := tr.post(t, tr.login(t, "agent-a", "pw-a"), alertBody("kept"), false); got != http.StatusCreated {
		t.Fatalf("post: HTTP %d", got)
	}
	tr.stop()

	l1.setDown(false)
	startRelay(t, testConfig(dir, l1))
	eventually(t, "delivery after restart", func() bool { return len(l1.received()) == 1 })
	if a := l1.received()[0]; a.machine != "agent-a" || a.scenario != "kept" {
		t.Errorf("after restart got %+v", a)
	}
}

func TestRejectedBatchDoesNotBlockQueue(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	l1.rejectNext = 1
	tr := startRelay(t, testConfig(t.TempDir(), l1))
	tok := tr.login(t, "agent-a", "pw-a")
	tr.post(t, tok, alertBody("poison"), false)
	tr.post(t, tok, alertBody("good"), false)
	eventually(t, "delivery past rejected batch", func() bool { return len(l1.received()) == 1 })
	if a := l1.received()[0]; a.scenario != "good" {
		t.Errorf("got %+v, want the batch after the rejected one", a)
	}
	q := tr.r.agents["agent-a"].queues[0]
	eventually(t, "empty queue", func() bool { return q.depth.Load() == 0 })
	if q.droppedCounts()["rejected"] != 1 {
		t.Errorf("dropped = %v, want 1 rejected", q.droppedCounts())
	}
}

func TestUpstreamTokenExpiry(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	tr := startRelay(t, testConfig(t.TempDir(), l1))
	tok := tr.login(t, "agent-a", "pw-a")
	tr.post(t, tok, alertBody("first"), false)
	eventually(t, "first delivery", func() bool { return len(l1.received()) == 1 })

	l1.expireTokens()
	tr.post(t, tok, alertBody("second"), false)
	eventually(t, "delivery after re-login", func() bool { return len(l1.received()) == 2 })
}

func TestAgentAuth(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	tr := startRelay(t, testConfig(t.TempDir(), l1))
	tests := []struct {
		name    string
		machine string
		pw      string
		ok      bool
	}{
		{"good", "agent-a", "pw-a", true},
		{"wrong password", "agent-a", "pw-b", false},
		{"other agent's password", "agent-b", "pw-a", false},
		{"unknown machine", "nobody", "pw-a", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tr.login(t, tc.machine, tc.pw) != ""; got != tc.ok {
				t.Errorf("login ok = %v, want %v", got, tc.ok)
			}
		})
	}
	if got := tr.post(t, "bogus", alertBody("x"), false); got != http.StatusUnauthorized {
		t.Errorf("post with bad token: HTTP %d, want 401 (the agent logs in again on 401)", got)
	}
}

func TestMalformedBatchIsNotQueued(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	dir := t.TempDir()
	tr := startRelay(t, testConfig(dir, l1))
	tok := tr.login(t, "agent-a", "pw-a")
	tests := []struct {
		name string
		body []byte
		gz   bool
	}{
		{"not json", []byte("hello"), false},
		{"object not array", []byte(`{"scenario":"x"}`), false},
		{"empty array", []byte(`[]`), false},
		{"bad gzip", []byte(`[{}]`), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tr.post(t, tok, tc.body, tc.gz); got != http.StatusBadRequest {
				t.Errorf("HTTP %d, want 400", got)
			}
		})
	}
	if n, _ := filepath.Glob(filepath.Join(dir, "lapi1", "agent-a", "*")); len(n) != 0 {
		t.Errorf("malformed batches were queued: %v", n)
	}
}

func TestQueueLimits(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	l1.setDown(true)
	cfg := testConfig(t.TempDir(), l1)
	cfg.MaxQueueFiles = 2
	tr := startRelay(t, cfg)
	tok := tr.login(t, "agent-a", "pw-a")
	for _, s := range []string{"old", "mid", "new"} {
		tr.post(t, tok, alertBody(s), false)
	}
	q := tr.r.agents["agent-a"].queues[0]
	if d := q.depth.Load(); d != 2 {
		t.Fatalf("depth = %d, want 2", d)
	}
	l1.setDown(false)
	q.signalRecovered()
	eventually(t, "delivery", func() bool { return len(l1.received()) == 2 })
	if got := l1.received(); got[0].scenario != "mid" || got[1].scenario != "new" {
		t.Errorf("got %+v, want the oldest batch dropped", got)
	}

	// Batches past max_queue_age are dropped rather than replayed.
	old := fmt.Sprintf("%020d-00000000.json", time.Now().Add(-8*24*time.Hour).UnixNano())
	os.WriteFile(filepath.Join(q.dir, old), alertBody("stale"), 0o600)
	q.added(int64(len(alertBody("stale"))))
	eventually(t, "stale batch dropped", func() bool { return q.droppedCounts()["expired"] == 1 })
	if n := len(l1.received()); n != 2 {
		t.Errorf("stale batch was delivered")
	}
}

func TestQueueByteLimit(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	l1.setDown(true)
	dir := t.TempDir()
	cfg := testConfig(dir, l1)
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	size := int64(len(alertBody("a1")))
	cfg.MaxQueueBytes = ByteSize(3 * size)
	tr := startValidated(t, cfg)
	ta, tb := tr.login(t, "agent-a", "pw-a"), tr.login(t, "agent-b", "pw-b")
	for _, p := range []struct{ tok, s string }{{ta, "a1"}, {ta, "a2"}, {tb, "b1"}, {ta, "a3"}, {tb, "b2"}} {
		if code := tr.post(t, p.tok, alertBody(p.s), false); code != http.StatusCreated {
			t.Fatalf("post %s: HTTP %d", p.s, code)
		}
	}
	qa, qb := tr.r.agents["agent-a"].queues[0], tr.r.agents["agent-b"].queues[0]
	// b2 pushed out a2, the oldest batch overall, although it is agent-a's.
	if got := tr.r.spool.totalBytes(); got != 3*size {
		t.Errorf("total bytes = %d, want %d", got, 3*size)
	}
	if d := qa.droppedCounts()["overflow"]; d != 2 {
		t.Errorf("agent-a overflow drops = %d, want 2", d)
	}
	if d := qb.droppedCounts()["overflow"]; d != 0 {
		t.Errorf("agent-b overflow drops = %d, want 0", d)
	}

	// Accounting after a restart comes from the files on disk.
	tr.stop()
	tr = startValidated(t, cfg)
	qa, qb = tr.r.agents["agent-a"].queues[0], tr.r.agents["agent-b"].queues[0]
	if qa.bytes.Load() != size || qb.bytes.Load() != 2*size {
		t.Errorf("after restart bytes = %d/%d, want %d/%d", qa.bytes.Load(), qb.bytes.Load(), size, 2*size)
	}

	l1.setDown(false)
	qa.signalRecovered()
	qb.signalRecovered()
	eventually(t, "delivery", func() bool { return len(l1.received()) == 3 })
	var got []string
	for _, a := range l1.received() {
		got = append(got, a.scenario)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "a3,b1,b2" {
		t.Errorf("delivered %v, want a3 b1 b2", got)
	}
	eventually(t, "queues empty", func() bool { return tr.r.spool.totalBytes() == 0 })
}

func TestOrphanQueues(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	dir := t.TempDir()
	stale := []string{
		filepath.Join(dir, "lapi-removed", "agent-a", "1-1.json"),
		filepath.Join(dir, "lapi1", "agent-renamed", "1-1.json"),
		filepath.Join(dir, "lapi1", "agent-renamed", "2-1.json"),
	}
	for _, p := range stale {
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, alertBody("old"), 0o600)
	}
	empty := filepath.Join(dir, "lapi1", "agent-empty")
	os.MkdirAll(empty, 0o700)

	tr := startRelay(t, testConfig(dir, l1))
	if tr.r.orphanBatches != 3 {
		t.Errorf("orphanBatches = %d, want 3", tr.r.orphanBatches)
	}
	for _, p := range stale {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was deleted without prune_orphan_queues", p)
		}
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Errorf("empty orphan queue was not removed")
	}
	tr.stop()

	cfg := testConfig(dir, l1)
	cfg.PruneOrphanQueues = true
	tr = startRelay(t, cfg)
	if tr.r.orphanBatches != 0 {
		t.Errorf("orphanBatches = %d after pruning, want 0", tr.r.orphanBatches)
	}
	for _, p := range []string{filepath.Join(dir, "lapi-removed"), filepath.Join(dir, "lapi1", "agent-renamed")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s was not pruned", p)
		}
	}
	for _, agent := range []string{"agent-a", "agent-b"} {
		if _, err := os.Stat(filepath.Join(dir, "lapi1", agent)); err != nil {
			t.Errorf("configured queue removed: %v", err)
		}
	}
}

func TestByteSize(t *testing.T) {
	for in, want := range map[string]int64{
		`1048576`: 1 << 20, `"1GiB"`: 1 << 30, `"100 MB"`: 100e6, `"2gb"`: 2e9, `"512"`: 512,
	} {
		var b ByteSize
		if err := json.Unmarshal([]byte(in), &b); err != nil || int64(b) != want {
			t.Errorf("%s: got %d, %v; want %d", in, b, err, want)
		}
	}
	for _, in := range []string{`"10XB"`, `"-1GiB"`, `"GiB"`, `"99999999999TiB"`, `true`} {
		var b ByteSize
		if err := json.Unmarshal([]byte(in), &b); err == nil {
			t.Errorf("%s: no error, got %d", in, b)
		}
	}
}

func TestHeartbeatAsAgent(t *testing.T) {
	l1 := newMockLAPI(t, bothAgents)
	tr := startRelay(t, testConfig(t.TempDir(), l1))
	tok := tr.login(t, "agent-a", "pw-a")
	req, _ := http.NewRequest(http.MethodGet, tr.url+"/v1/heartbeat", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: HTTP %d", resp.StatusCode)
	}
	// The loop's first round runs at startup, before the agent was seen;
	// run one round by hand rather than waiting a minute.
	tr.r.heartbeatRound(context.Background())
	l1.mu.Lock()
	defer l1.mu.Unlock()
	if l1.heartbeats["agent-a"] != 1 || l1.heartbeats["agent-b"] != 0 {
		t.Errorf("heartbeats = %v, want one for the active agent only", l1.heartbeats)
	}
}

func TestBadUserAgentFallsBack(t *testing.T) {
	a := &agentState{}
	a.updateLogin(nil, "Mozilla/5.0 (X11; Linux) Firefox/1")
	if _, ua, _ := a.loginInfo(); ua != "lapi-relay/"+version {
		t.Errorf("ua = %q, want the relay's own (the LAPI refuses a UA with more than one '/')", ua)
	}
	gen := a.generation()
	a.updateLogin([]string{"b", "a"}, "crowdsec/v1")
	a.updateLogin([]string{"a", "b"}, "crowdsec/v1")
	if a.generation() != gen+1 {
		t.Errorf("same scenarios in another order forced a second upstream login")
	}
}

func TestConfigValidation(t *testing.T) {
	base := func() *Config {
		return &Config{
			QueueDir: "/tmp/q",
			Agents:   []AgentConfig{{Login: "agent", Password: "x"}},
			LAPIs:    []UpstreamConfig{{Name: "lapi-a", URL: "http://lapi-a.example:8080/"}},
		}
	}
	tests := []struct {
		name    string
		mod     func(*Config)
		wantErr string
	}{
		{"defaults", func(*Config) {}, ""},
		{"shared address space listen", func(c *Config) { c.Listen = "100.101.102.103:8081" }, ""},
		{"ula listen", func(c *Config) { c.Listen = "[fd00::1]:8081" }, ""},
		{"private listen", func(c *Config) { c.Listen = "192.168.1.5:8081" }, ""},
		{"all interfaces", func(c *Config) { c.Listen = ":8081" }, "host must be an IP"},
		{"unspecified", func(c *Config) { c.Listen = "0.0.0.0:8081" }, "not a loopback"},
		{"public", func(c *Config) { c.Listen = "8.8.8.8:8081" }, "not a loopback"},
		{"public allowed", func(c *Config) { c.Listen = "0.0.0.0:8081"; c.AllowPublicListen = true }, ""},
		{"no lapis", func(c *Config) { c.LAPIs = nil }, "lapis is required"},
		{"queue bytes too small", func(c *Config) {
			c.LAPIs = append(c.LAPIs, UpstreamConfig{Name: "lapi-b", URL: "http://lapi-b.example:8080/"})
			c.MaxQueueBytes = 40 << 20
		}, "at least 64 MiB"},
		{"bad url", func(c *Config) { c.LAPIs[0].URL = "100.1.1.1:8080" }, "must be http(s)"},
		{"dup lapi", func(c *Config) { c.LAPIs = append(c.LAPIs, c.LAPIs[0]) }, "duplicate name"},
		{"path in login", func(c *Config) { c.Agents[0].Login = "../etc" }, "must match"},
		{"no password", func(c *Config) { c.Agents[0].Password = "" }, "password or password_file is required"},
		{"unknown upstream", func(c *Config) {
			c.Agents[0].Upstream = map[string]CredentialConfig{"lapi-z": {Password: "y"}}
		}, "not in lapis"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mod(c)
			err := c.validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestPerLAPICredentials(t *testing.T) {
	l1 := newMockLAPI(t, map[string]string{"agent-a": "pw-a", "agent-b": "pw-b"})
	l2 := newMockLAPI(t, map[string]string{"agent-a-alt": "other", "agent-b": "pw-b"})
	cfg := testConfig(t.TempDir(), l1, l2)
	cfg.Agents[0].Upstream = map[string]CredentialConfig{"lapi2": {Login: "agent-a-alt", Password: "other"}}
	tr := startRelay(t, cfg)
	tr.post(t, tr.login(t, "agent-a", "pw-a"), alertBody("x"), false)
	eventually(t, "lapi2 delivery", func() bool { return len(l2.received()) == 1 })
	if m := l2.received()[0].machine; m != "agent-a-alt" {
		t.Errorf("lapi2 recorded machine %q, want the per-LAPI login", m)
	}
	eventually(t, "lapi1 delivery", func() bool { return len(l1.received()) == 1 })
	if m := l1.received()[0].machine; m != "agent-a" {
		t.Errorf("lapi1 recorded machine %q, want agent-a", m)
	}
}
