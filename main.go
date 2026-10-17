// lapi-relay accepts alerts from CrowdSec log processors and delivers them to
// several independent Local APIs, queueing on disk for any LAPI that is down.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var version = "0.2.0"

func main() {
	cfgPath := flag.String("c", "/etc/lapi-relay/config.json", "config file")
	check := flag.Bool("check", false, "validate the config and exit")
	debug := flag.Bool("debug", false, "debug logging")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("invalid config", "err", err)
		os.Exit(2)
	}
	if *check {
		fmt.Println("config OK")
		return
	}
	if err := run(cfg); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(cfg *Config) error {
	r, err := newRelay(cfg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, r, ln)
}

// serve runs until ctx is done, then stops taking alerts and gives the
// queues up to ShutdownGrace to drain. Anything left stays on disk.
func serve(ctx context.Context, r *relay, ln net.Listener) error {
	workCtx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()
	var wg sync.WaitGroup
	for _, q := range r.allQueues() {
		wg.Add(1)
		go func() { defer wg.Done(); q.run(workCtx) }()
	}
	wg.Add(2)
	go func() { defer wg.Done(); r.heartbeatLoop(workCtx) }()
	go func() { defer wg.Done(); r.depthLogLoop(workCtx) }()

	srv := &http.Server{Handler: r.handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	slog.Info("lapi-relay listening", "addr", ln.Addr().String(), "version", version, "lapis", len(r.lapis), "agents", len(r.agents))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(sctx)
	cancel()

	grace := time.Duration(r.cfg.ShutdownGrace)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) && pending(r) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
	cancelWork()
	wg.Wait()
	if n := pending(r); n > 0 {
		slog.Warn("batches left on disk, will be delivered after restart", "pending", n)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func pending(r *relay) int64 {
	var n int64
	for _, q := range r.allQueues() {
		if q.up.Load() { // don't wait on a LAPI that is down
			n += q.depth.Load()
		}
	}
	return n
}
