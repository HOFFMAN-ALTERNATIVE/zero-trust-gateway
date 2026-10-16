// Package audit writes one structured JSON record per access decision.
// Records are append-only facts meant for a SIEM: who, what, which rule, outcome.
package audit

import (
	"context"
	"io"
	"log/slog"
	"time"
)

// Event is a single access decision.
type Event struct {
	RequestID string
	RemoteIP  string
	Method    string
	Host      string
	Path      string
	Route     string
	Upstream  string
	Subject   string
	Email     string
	Groups    []string
	AuthnVia  string // bearer | session | none
	Decision  string // allow | deny
	Rule      string
	Reason    string
	Status    int
	Duration  time.Duration
}

// Logger emits audit events.
type Logger struct{ l *slog.Logger }

// New writes JSON lines to w.
func New(w io.Writer) *Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				a.Key = "event"
			}
			return a
		},
	})
	return &Logger{l: slog.New(h).With("log", "audit")}
}

// Log records e.
func (a *Logger) Log(ctx context.Context, e Event) {
	attrs := []slog.Attr{
		slog.String("request_id", e.RequestID),
		slog.String("remote_ip", e.RemoteIP),
		slog.String("method", e.Method),
		slog.String("host", e.Host),
		slog.String("path", e.Path),
		slog.String("route", e.Route),
		slog.String("decision", e.Decision),
		slog.String("reason", e.Reason),
		slog.Int("status", e.Status),
		slog.String("authn", e.AuthnVia),
		slog.Float64("duration_ms", float64(e.Duration.Microseconds())/1000),
	}
	if e.Upstream != "" {
		attrs = append(attrs, slog.String("upstream", e.Upstream))
	}
	if e.Rule != "" {
		attrs = append(attrs, slog.String("rule", e.Rule))
	}
	if e.Subject != "" {
		attrs = append(attrs, slog.String("sub", e.Subject), slog.String("email", e.Email), slog.Any("groups", e.Groups))
	}
	a.l.LogAttrs(ctx, slog.LevelInfo, "access", attrs...)
}
