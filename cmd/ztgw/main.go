// Command ztgw runs the zero-trust gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/config"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/gateway"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to the gateway config")
	auditPath := flag.String("audit-log", "-", "audit log destination (- = stdout)")
	drainDelay := flag.Duration("drain-delay", 2*time.Second, "time between failing /readyz and closing listeners")
	healthcheck := flag.String("healthcheck", "", "probe URL and exit 0/1 (for distroless container healthchecks)")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *healthcheck != "" {
		os.Exit(probe(*healthcheck))
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "ztgw", "version", version)
	if err := run(*cfgPath, *auditPath, *drainDelay, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func probe(u string) int {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(u) //nolint:gosec,noctx // operator-supplied probe URL
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run(cfgPath, auditPath string, drainDelay time.Duration, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	var auditW io.Writer = os.Stdout
	if auditPath != "-" {
		f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // operator-supplied
		if err != nil {
			return err
		}
		defer f.Close()
		auditW = f
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var gw *gateway.Gateway
	// Discovery may race the IdP at boot (compose, k8s): retry with backoff.
	for attempt := 1; ; attempt++ {
		gw, err = gateway.New(ctx, cfg, gateway.Options{Audit: auditW, Logger: log})
		if err == nil {
			break
		}
		if attempt == 10 || ctx.Err() != nil {
			return err
		}
		log.Warn("gateway init failed, retrying", "attempt", attempt, "err", err)
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
	}
	go gw.Warmup(ctx)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			nc, err := config.Load(cfgPath)
			if err == nil {
				err = gw.ReloadPolicy(nc.Routes)
			}
			if err != nil {
				log.Error("policy reload rejected; keeping previous policy", "err", err)
				continue
			}
			log.Info("policy reloaded", "routes", len(nc.Routes))
		}
	}()

	public := &http.Server{
		Addr:              cfg.Listen,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // streaming responses; upstream timeouts bound the work
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	admin := &http.Server{Addr: cfg.AdminListen, Handler: gw.AdminHandler(), ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	for _, s := range []*http.Server{public, admin} {
		go func() {
			log.Info("listening", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutdown: draining", "delay", drainDelay.String())
	gw.Drain()
	time.Sleep(drainDelay)
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownWait.Duration)
	defer cancel()
	err = errors.Join(public.Shutdown(sctx), admin.Shutdown(sctx))
	log.Info("shutdown complete", "err", err)
	return err
}
