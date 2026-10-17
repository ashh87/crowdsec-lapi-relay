package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Queue layout: <queue_dir>/<lapi>/<agent>/<unixnano>-<seq>.json[.gz]
// A batch is written once to <queue_dir>/tmp, fsynced, then hard-linked into
// every LAPI's directory for that agent, so the agent gets its 201 only when
// each LAPI has a durable copy. Deleting a link after delivery leaves the
// others in place.

type spool struct {
	dir string
	seq atomic.Uint64
}

func newSpool(dir string) (*spool, error) {
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o700); err != nil {
		return nil, err
	}
	// Leftovers from a crash between write and link were never acknowledged.
	if ents, err := os.ReadDir(filepath.Join(dir, "tmp")); err == nil {
		for _, e := range ents {
			os.Remove(filepath.Join(dir, "tmp", e.Name()))
		}
	}
	return &spool{dir: dir}, nil
}

// enqueue makes body durable in every queue. On error, links already made
// are kept (a duplicate on retry is better than a loss) and the caller should
// tell the agent to retry.
func (s *spool) enqueue(body []byte, gzipped bool, queues []*queue) error {
	name := fmt.Sprintf("%020d-%08d.json", time.Now().UnixNano(), s.seq.Add(1)%1e8)
	if gzipped {
		name += ".gz"
	}
	tmp := filepath.Join(s.dir, "tmp", name)
	if err := writeSync(tmp, body); err != nil {
		os.Remove(tmp)
		return err
	}
	defer os.Remove(tmp)
	var errs []error
	for _, q := range queues {
		if err := os.Link(tmp, filepath.Join(q.dir, name)); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := syncDir(q.dir); err != nil {
			errs = append(errs, err)
		}
		q.added()
	}
	return errors.Join(errs...)
}

func writeSync(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// queue holds one agent's undelivered batches for one LAPI.
type queue struct {
	dir     string
	sess    *session
	maxN    int
	maxAge  time.Duration
	notify  chan struct{}
	recover chan struct{}
	log     *slog.Logger

	depth     atomic.Int64
	up        atomic.Bool
	delivered atomic.Uint64
	mu        sync.Mutex
	dropped   map[string]uint64 // reason -> count
}

func newQueue(root string, sess *session, maxN int, maxAge time.Duration) (*queue, error) {
	dir := filepath.Join(root, sess.lapi.name, sess.agent.cfg.Login)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	q := &queue{
		dir: dir, sess: sess, maxN: maxN, maxAge: maxAge,
		notify:  make(chan struct{}, 1),
		recover: make(chan struct{}, 1),
		dropped: map[string]uint64{},
		log:     slog.With("lapi", sess.lapi.name, "agent", sess.agent.cfg.Login),
	}
	names, err := q.list()
	if err != nil {
		return nil, err
	}
	q.depth.Store(int64(len(names)))
	if len(names) > 0 {
		q.log.Info("pending batches from before restart", "depth", len(names))
	}
	return q, nil
}

func (q *queue) list() ([]string, error) {
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if n := e.Name(); e.Type().IsRegular() && (strings.HasSuffix(n, ".json") || strings.HasSuffix(n, ".json.gz")) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (q *queue) added() {
	if q.depth.Add(1) > int64(q.maxN) && q.maxN > 0 {
		q.trim()
	}
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *queue) trim() {
	names, err := q.list()
	if err != nil {
		return
	}
	for len(names) > q.maxN {
		q.remove(names[0], "overflow")
		names = names[1:]
	}
}

func (q *queue) remove(name, dropReason string) {
	if err := os.Remove(filepath.Join(q.dir, name)); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			q.log.Error("removing queued batch", "file", name, "err", err)
		}
		return
	}
	q.depth.Add(-1)
	if dropReason != "" {
		q.mu.Lock()
		q.dropped[dropReason]++
		q.mu.Unlock()
		q.log.Warn("dropped queued batch", "file", name, "reason", dropReason)
	}
}

func (q *queue) droppedCounts() map[string]uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make(map[string]uint64, len(q.dropped))
	for k, v := range q.dropped {
		out[k] = v
	}
	return out
}

func batchTime(name string) time.Time {
	var ns int64
	fmt.Sscanf(name, "%020d", &ns)
	return time.Unix(0, ns)
}

func (q *queue) setUp(up bool) {
	if q.up.Swap(up) != up {
		if up {
			q.log.Info("LAPI reachable", "pending", q.depth.Load())
		} else {
			q.log.Warn("LAPI unreachable, queueing", "pending", q.depth.Load())
		}
	}
}

// signalRecovered cuts a retry backoff short, e.g. after a good heartbeat.
func (q *queue) signalRecovered() {
	select {
	case q.recover <- struct{}{}:
	default:
	}
}

// run delivers batches oldest first until ctx is cancelled.
func (q *queue) run(ctx context.Context) {
	const minBackoff, maxBackoff = time.Second, time.Minute
	backoff := minBackoff
	for ctx.Err() == nil {
		names, err := q.list()
		if err != nil {
			q.log.Error("listing queue", "err", err)
		}
		if len(names) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-q.notify:
			case <-time.After(30 * time.Second):
			}
			continue
		}
		failed := false
		for _, name := range names {
			if q.maxAge > 0 && time.Since(batchTime(name)) > q.maxAge {
				q.remove(name, "expired")
				continue
			}
			body, err := os.ReadFile(filepath.Join(q.dir, name))
			if errors.Is(err, os.ErrNotExist) {
				continue // trimmed meanwhile
			} else if err != nil {
				q.log.Error("reading queued batch", "file", name, "err", err)
				failed = true
				break
			}
			err = q.sess.postAlerts(ctx, body, strings.HasSuffix(name, ".gz"))
			switch {
			case err == nil:
				q.remove(name, "")
				q.delivered.Add(1)
				q.setUp(true)
				backoff = minBackoff
			case isRejected(err):
				// Poison batch: keeping it would block everything behind it.
				q.setUp(true)
				q.log.Error("LAPI rejected batch, dropping it", "file", name, "err", err)
				q.remove(name, "rejected")
			default:
				if ctx.Err() != nil {
					return
				}
				q.log.Debug("delivery failed", "file", name, "err", err)
				if q.up.Load() {
					q.log.Warn("delivery failed", "err", err)
				}
				q.setUp(false)
				failed = true
			}
			if failed || ctx.Err() != nil {
				break
			}
		}
		if failed {
			select {
			case <-ctx.Done():
				return
			case <-q.recover:
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, maxBackoff)
		}
	}
}
