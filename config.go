package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that reads "90s" / "24h" from JSON.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// ByteSize reads a number of bytes, or a string like "512MiB" or "1GB".
type ByteSize int64

var byteUnits = map[string]int64{
	"": 1, "b": 1,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
}

func (b *ByteSize) UnmarshalJSON(data []byte) error {
	var n int64
	if err := json.Unmarshal(data, &n); err == nil {
		*b = ByteSize(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.New("size must be a number of bytes or a string like \"1GiB\"")
	}
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if i < 0 {
		i = len(s)
	}
	v, err := strconv.ParseInt(s[:i], 10, 64)
	mult, ok := byteUnits[strings.ToLower(strings.TrimSpace(s[i:]))]
	if err != nil || !ok || v > math.MaxInt64/mult {
		return fmt.Errorf("size %q: want a number with an optional unit (B, KB, MB, GB, TB, KiB, MiB, GiB, TiB)", s)
	}
	*b = ByteSize(v * mult)
	return nil
}

type Config struct {
	// Listen is host:port. Only loopback, RFC 1918, IPv6 ULA and RFC 6598 shared
	// (100.64.0.0/10, used by CGNAT and VPN overlays) addresses are accepted
	// unless AllowPublicListen is set.
	Listen            string `json:"listen"`
	AllowPublicListen bool   `json:"allow_public_listen"`
	// Optional. Agents send their password at login, so use TLS unless the
	// path to the relay is already private (loopback, an encrypted VPN).
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`

	QueueDir string `json:"queue_dir"`
	// Per agent and LAPI. Past this the oldest batch is dropped.
	MaxQueueFiles int `json:"max_queue_files"`
	// Batches older than this are dropped instead of replayed. The LAPI sets a
	// decision's expiry from the alert's stop_at, not from when it arrives, so a
	// late replay never extends a ban; it only adds alert history (which
	// duration_expr profiles such as GetDecisionsCount do read).
	MaxQueueAge Duration `json:"max_queue_age"`
	// Total across all queues, counting a batch once per LAPI it waits for.
	// Past this the oldest batches are dropped, whichever queue they are in.
	MaxQueueBytes ByteSize `json:"max_queue_bytes"`
	// Delete queues for agents or LAPIs that are no longer in the config,
	// instead of only warning about them at startup.
	PruneOrphanQueues bool `json:"prune_orphan_queues"`

	TokenTTL      Duration `json:"token_ttl"`
	ShutdownGrace Duration `json:"shutdown_grace"`

	Agents []AgentConfig    `json:"agents"`
	LAPIs  []UpstreamConfig `json:"lapis"`
}

// AgentConfig is a log processor allowed to use the relay. By default the relay
// logs in to every LAPI with the same login and password, so each LAPI records
// the agent's own machine ID on its alerts. Upstream overrides that per LAPI.
type AgentConfig struct {
	Login        string                      `json:"login"`
	Password     string                      `json:"password"`
	PasswordFile string                      `json:"password_file"`
	Upstream     map[string]CredentialConfig `json:"upstream"`
}

type CredentialConfig struct {
	Login        string `json:"login"`
	Password     string `json:"password"`
	PasswordFile string `json:"password_file"`
}

type UpstreamConfig struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	CAFile string `json:"ca_file"`
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var sharedAddrSpace = netip.MustParsePrefix("100.64.0.0/10") // RFC 6598

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	cfg := &Config{}
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8081"
	}
	if c.MaxQueueFiles == 0 {
		c.MaxQueueFiles = 10000
	}
	if c.MaxQueueAge == 0 {
		c.MaxQueueAge = Duration(7 * 24 * time.Hour)
	}
	if c.MaxQueueBytes == 0 {
		c.MaxQueueBytes = 1 << 30
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = Duration(time.Hour)
	}
	if c.ShutdownGrace == 0 {
		c.ShutdownGrace = Duration(10 * time.Second)
	}

	var errs []error
	if err := checkListen(c.Listen, c.AllowPublicListen); err != nil {
		errs = append(errs, err)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, errors.New("set both tls_cert and tls_key, or neither"))
	}
	if c.QueueDir == "" {
		errs = append(errs, errors.New("queue_dir is required"))
	}
	if c.MaxQueueFiles < 0 || c.MaxQueueAge < 0 || c.TokenTTL < Duration(2*time.Minute) {
		errs = append(errs, errors.New("max_queue_files and max_queue_age must be >= 0, token_ttl >= 2m"))
	}

	if len(c.LAPIs) == 0 {
		errs = append(errs, errors.New("at least one entry in lapis is required"))
	}
	// The largest batch the relay accepts must fit, or it would be dropped
	// right after the agent was told it was stored.
	if minBytes := ByteSize(maxBodySize * max(len(c.LAPIs), 1)); c.MaxQueueBytes < minBytes {
		errs = append(errs, fmt.Errorf("max_queue_bytes must be at least %d MiB (32 MiB per LAPI)", minBytes>>20))
	}
	lapis := map[string]bool{}
	for i, u := range c.LAPIs {
		if !nameRE.MatchString(u.Name) {
			errs = append(errs, fmt.Errorf("lapis[%d]: name %q must match %s", i, u.Name, nameRE))
		}
		if lapis[u.Name] {
			errs = append(errs, fmt.Errorf("lapis[%d]: duplicate name %q", i, u.Name))
		}
		lapis[u.Name] = true
		pu, err := url.Parse(u.URL)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			errs = append(errs, fmt.Errorf("lapis[%d]: url %q must be http(s)://host[:port]/", i, u.URL))
		}
	}

	if len(c.Agents) == 0 {
		errs = append(errs, errors.New("at least one entry in agents is required"))
	}
	agents := map[string]bool{}
	for i := range c.Agents {
		a := &c.Agents[i]
		// The login names a queue directory, hence the restriction.
		if !nameRE.MatchString(a.Login) {
			errs = append(errs, fmt.Errorf("agents[%d]: login %q must match %s", i, a.Login, nameRE))
		}
		if agents[a.Login] {
			errs = append(errs, fmt.Errorf("agents[%d]: duplicate login %q", i, a.Login))
		}
		agents[a.Login] = true
		pw, err := resolvePassword(a.Password, a.PasswordFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("agents[%d] (%s): %w", i, a.Login, err))
		}
		a.Password, a.PasswordFile = pw, ""
		for name, cred := range a.Upstream {
			if !lapis[name] {
				errs = append(errs, fmt.Errorf("agents[%d] (%s): upstream %q is not in lapis", i, a.Login, name))
				continue
			}
			if cred.Login == "" {
				cred.Login = a.Login
			}
			pw, err := resolvePassword(cred.Password, cred.PasswordFile)
			if err != nil {
				errs = append(errs, fmt.Errorf("agents[%d] (%s) upstream %s: %w", i, a.Login, name, err))
			}
			cred.Password, cred.PasswordFile = pw, ""
			a.Upstream[name] = cred
		}
	}
	return errors.Join(errs...)
}

// credentialsFor returns what the relay logs in to LAPI name with on behalf of a.
func (a *AgentConfig) credentialsFor(name string) (string, string) {
	if c, ok := a.Upstream[name]; ok {
		return c.Login, c.Password
	}
	return a.Login, a.Password
}

func resolvePassword(inline, file string) (string, error) {
	switch {
	case inline != "" && file != "":
		return "", errors.New("set password or password_file, not both")
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		pw := strings.TrimRight(string(b), "\r\n")
		if pw == "" {
			return "", fmt.Errorf("%s is empty", file)
		}
		return pw, nil
	case inline != "":
		return inline, nil
	}
	return "", errors.New("password or password_file is required")
}

func checkListen(listen string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("listen %q: %w", listen, err)
	}
	if allowPublic {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("listen %q: host must be an IP address or localhost", listen)
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || sharedAddrSpace.Contains(ip) {
		return nil
	}
	return fmt.Errorf("listen %q: not a loopback, private or 100.64.0.0/10 address (set allow_public_listen to override)", listen)
}
