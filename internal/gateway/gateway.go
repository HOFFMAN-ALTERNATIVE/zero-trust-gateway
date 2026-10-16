// Package gateway is the identity-aware reverse proxy: it authenticates every
// request (bearer JWT or session cookie), evaluates the per-route policy and
// forwards allowed requests to upstreams over mutual TLS.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/audit"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/config"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/jwtverify"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/metrics"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/oidc"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/policy"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/session"
)

// Identity headers injected for upstreams. Any inbound header with this
// prefix is stripped first, so clients cannot spoof an identity.
const (
	HeaderPrefix  = "X-Auth-Request-"
	HeaderUser    = HeaderPrefix + "User"
	HeaderEmail   = HeaderPrefix + "Email"
	HeaderGroups  = HeaderPrefix + "Groups"
	HeaderAuthn   = HeaderPrefix + "Method"
	HeaderRequest = "X-Request-Id"
	reservedPath  = "/_ztg/"
)

// Options are runtime dependencies (injectable for tests).
type Options struct {
	IDPClient *http.Client // talks to the issuer (discovery, JWKS, token)
	Audit     io.Writer
	Logger    *slog.Logger
	Now       func() time.Time
}

// Gateway is safe for concurrent use.
type Gateway struct {
	cfg       *config.Config
	verifier  *jwtverify.Verifier
	sessions  *session.Manager
	oidc      *oidc.Client
	engine    atomic.Pointer[policy.Engine]
	upstreams map[string]*upstream
	audit     *audit.Logger
	metrics   *metrics.Metrics
	log       *slog.Logger
	now       func() time.Time
	draining  atomic.Bool
	flowName  string
}

// New wires the gateway. It performs OIDC discovery when endpoints are not
// configured explicitly; JWKS is fetched lazily / by Warmup.
func New(ctx context.Context, cfg *config.Config, o Options) (*Gateway, error) {
	if o.IDPClient == nil {
		o.IDPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Audit == nil {
		o.Audit = io.Discard
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	g := &Gateway{cfg: cfg, audit: audit.New(o.Audit), metrics: metrics.New(), log: o.Logger, now: o.Now}

	ep := oidc.Endpoints{
		Issuer:                cfg.OIDC.Issuer,
		AuthorizationEndpoint: cfg.OIDC.AuthorizationEndpoint,
		TokenEndpoint:         cfg.OIDC.TokenEndpoint,
		JWKSURI:               cfg.OIDC.JWKSURI,
	}
	if ep.AuthorizationEndpoint == "" || ep.TokenEndpoint == "" || ep.JWKSURI == "" {
		d, err := oidc.Discover(ctx, o.IDPClient, cfg.OIDC.Issuer)
		if err != nil {
			return nil, err
		}
		ep = *d
	}
	keys := jwtverify.NewKeySet(ep.JWKSURI, jwtverify.KeySetOptions{
		HTTPClient: o.IDPClient,
		MinRefresh: cfg.OIDC.JWKSMinRefresh.Duration,
		Now:        o.Now,
		OnRefresh: func(err error, n int) {
			res := "ok"
			if err != nil {
				res = "error"
			}
			g.metrics.JWKSRefresh.WithLabelValues(res).Inc()
			g.metrics.JWKSKeys.Set(float64(n))
		},
	})
	v, err := jwtverify.NewVerifier(jwtverify.Config{
		Issuer: cfg.OIDC.Issuer, Audience: cfg.OIDC.Audience, Algorithms: cfg.OIDC.Algorithms,
		Leeway: cfg.OIDC.Leeway.Duration, Now: o.Now,
	}, keys)
	if err != nil {
		return nil, err
	}
	g.verifier = v
	g.sessions, err = session.New(session.Options{Keys: cfg.Session.Keys, TTL: cfg.Session.TTL.Duration, Secure: *cfg.Session.Secure, Now: o.Now})
	if err != nil {
		return nil, err
	}
	g.flowName = "ztg_flow"
	if *cfg.Session.Secure {
		g.flowName = "__Host-ztg_flow"
	}
	g.oidc = &oidc.Client{
		Endpoints: ep, ClientID: cfg.OIDC.ClientID, ClientSecret: cfg.OIDC.ClientSecret,
		RedirectURI: strings.TrimSuffix(cfg.PublicURL, "/") + reservedPath + "callback",
		Scopes:      cfg.OIDC.Scopes, HTTP: o.IDPClient,
	}
	g.upstreams = map[string]*upstream{}
	for name, u := range cfg.Upstreams {
		up, err := g.newUpstream(name, u)
		if err != nil {
			return nil, err
		}
		g.upstreams[name] = up
	}
	if err := g.ReloadPolicy(cfg.Routes); err != nil {
		return nil, err
	}
	return g, nil
}

// ReloadPolicy validates routes and atomically swaps them in. In-flight
// requests finish with the policy they started with.
func (g *Gateway) ReloadPolicy(routes []policy.Route) error {
	ups := map[string]bool{}
	for n := range g.upstreams {
		ups[n] = true
	}
	e, err := policy.New(routes, ups)
	if err != nil {
		g.metrics.Reloads.WithLabelValues("error").Inc()
		return err
	}
	g.engine.Store(e)
	g.metrics.Reloads.WithLabelValues("ok").Inc()
	return nil
}

// Metrics exposes the instruments (tests, embedding).
func (g *Gateway) Metrics() *metrics.Metrics { return g.metrics }

// Warmup fetches the JWKS, retrying until success or ctx is done, then keeps
// it fresh in the background. Readiness depends on the first success.
func (g *Gateway) Warmup(ctx context.Context) {
	backoff := 250 * time.Millisecond
	for !g.verifier.KeySet().Ready() {
		if err := g.verifier.KeySet().Refresh(ctx); err != nil {
			g.log.Warn("jwks warmup failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 5*time.Second)
		}
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := g.verifier.KeySet().Refresh(ctx); err != nil {
				g.log.Warn("jwks refresh failed; serving cached keys", "err", err)
			}
		}
	}
}

// Drain flips readiness to false so load balancers stop sending traffic
// before the listener is shut down.
func (g *Gateway) Drain() { g.draining.Store(true) }

// AdminHandler serves /healthz, /readyz and /metrics (bind it to a private port).
func (g *Gateway) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		switch {
		case g.draining.Load():
			http.Error(w, "draining", http.StatusServiceUnavailable)
		case !g.verifier.KeySet().Ready():
			http.Error(w, "jwks not loaded", http.StatusServiceUnavailable)
		default:
			_, _ = io.WriteString(w, "ready\n")
		}
	})
	mux.Handle("GET /metrics", g.metrics.Handler())
	return mux
}

// Handler is the public entrypoint.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+reservedPath+"login", g.login)
	mux.HandleFunc("GET "+reservedPath+"callback", g.callback)
	mux.HandleFunc(reservedPath+"logout", g.logout)
	mux.HandleFunc("GET "+reservedPath+"whoami", g.whoami)
	mux.HandleFunc(reservedPath, func(w http.ResponseWriter, r *http.Request) { writeError(w, r, http.StatusNotFound, "not found") })
	mux.HandleFunc("/", g.serveProxy)
	return g.withRequestID(mux)
}

// ---- request state -------------------------------------------------------

type ctxKey struct{}

type reqState struct {
	id          string
	identity    *policy.Identity
	route       *policy.Route
	path        string
	upstreamErr error
}

func stateFrom(ctx context.Context) *reqState {
	s, _ := ctx.Value(ctxKey{}).(*reqState)
	return s
}

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

func (g *Gateway) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequest)
		if !g.cfg.TrustedProxy || !requestIDRe.MatchString(id) {
			id = session.RandomID()
		}
		w.Header().Set(HeaderRequest, id)
		st := &reqState{id: id}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, st)))
	})
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush/Hijack on the real writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (g *Gateway) clientIP(r *http.Request) string {
	if g.cfg.TrustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- authentication -------------------------------------------------------

var errNoCredentials = errors.New("no credentials")

// authenticate returns the caller's identity. A presented-but-invalid bearer
// token is an error (never silently downgraded to anonymous).
func (g *Gateway) authenticate(r *http.Request) (*policy.Identity, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, tok, ok := strings.Cut(h, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
			return nil, fmt.Errorf("%w: unsupported authorization scheme", jwtverify.ErrMalformed)
		}
		c, err := g.verifier.Verify(r.Context(), strings.TrimSpace(tok), "")
		if err != nil {
			return nil, err
		}
		return &policy.Identity{Subject: c.Subject, Email: c.Email, Groups: c.Groups, Claims: c.Raw, Method: "bearer"}, nil
	}
	if ck, err := r.Cookie(g.sessions.CookieName()); err == nil {
		s, err := g.sessions.Verify(ck.Value)
		if err != nil {
			return nil, err
		}
		claims := map[string]any{"sub": s.Subject, "email": s.Email, "groups": toAny(s.Groups)}
		return &policy.Identity{Subject: s.Subject, Email: s.Email, Groups: s.Groups, Claims: claims, Method: "session"}, nil
	}
	return nil, errNoCredentials
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func authnReason(err error) string {
	switch {
	case errors.Is(err, session.ErrExpired):
		return "session_expired"
	case errors.Is(err, session.ErrInvalid):
		return "session_invalid"
	default:
		return jwtverify.Reason(err)
	}
}

// ---- proxy path -----------------------------------------------------------

func wantsHTML(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html") && r.Header.Get("Authorization") == ""
}

// ambiguousPath rejects encodings that upstreams may decode differently from
// the gateway (encoded slash / backslash / NUL), a classic policy bypass.
func ambiguousPath(r *http.Request) bool {
	raw := strings.ToLower(r.URL.EscapedPath())
	return strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") || strings.Contains(raw, "%00") || strings.ContainsRune(r.URL.Path, '\\')
}

func (g *Gateway) serveProxy(w http.ResponseWriter, r *http.Request) {
	start := g.now()
	st := stateFrom(r.Context())
	rec := &recorder{ResponseWriter: w}
	ev := audit.Event{RequestID: st.id, RemoteIP: g.clientIP(r), Method: r.Method, Host: r.Host, AuthnVia: "none"}

	defer func() {
		ev.Status = rec.status
		ev.Duration = g.now().Sub(start)
		if st.upstreamErr != nil {
			ev.Reason = "upstream error: " + st.upstreamErr.Error()
		}
		routeLabel := ev.Route
		if routeLabel == "" {
			routeLabel = "none"
		}
		g.metrics.Requests.WithLabelValues(routeLabel, ev.Decision, fmt.Sprint(ev.Status)).Inc()
		g.metrics.Duration.WithLabelValues(routeLabel).Observe(ev.Duration.Seconds())
		g.audit.Log(r.Context(), ev)
	}()

	if ambiguousPath(r) {
		ev.Path, ev.Decision, ev.Reason = r.URL.EscapedPath(), "deny", "ambiguous path encoding"
		writeError(rec, r, http.StatusBadRequest, "ambiguous path encoding")
		return
	}
	p := policy.CleanPath(r.URL.Path)
	ev.Path = p
	st.path = p
	route := g.engine.Load().Route(r.Host, p)

	id, authErr := g.authenticate(r)
	if authErr != nil && !errors.Is(authErr, errNoCredentials) {
		g.metrics.AuthnFailures.WithLabelValues(authnReason(authErr)).Inc()
	}
	if id != nil {
		ev.Subject, ev.Email, ev.Groups, ev.AuthnVia = id.Subject, id.Email, id.Groups, id.Method
	}

	d := policy.Evaluate(route, id, r.Method, p)
	if route != nil {
		ev.Route, ev.Upstream = route.Name, route.Upstream
	}
	ev.Rule, ev.Reason = d.Rule, d.Reason

	// An invalid credential is rejected even on public routes: a client that
	// sends a bad token has a bug or is probing, and should hear about it.
	if authErr != nil && !errors.Is(authErr, errNoCredentials) && r.Header.Get("Authorization") != "" {
		ev.Decision, ev.Reason = "deny", "invalid credentials: "+authnReason(authErr)
		w.Header().Set("WWW-Authenticate", `Bearer realm="ztg", error="invalid_token"`)
		writeError(rec, r, http.StatusUnauthorized, "invalid token")
		return
	}

	if !d.Allow {
		ev.Decision = "deny"
		if d.Status == http.StatusUnauthorized {
			if wantsHTML(r) {
				http.Redirect(rec, r, reservedPath+"login?rd="+urlQueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="ztg"`)
		}
		writeError(rec, r, d.Status, strings.ToLower(http.StatusText(d.Status)))
		return
	}
	ev.Decision = "allow"
	st.identity, st.route = id, route
	g.upstreams[route.Upstream].proxy.ServeHTTP(rec, r)
}

func (g *Gateway) reservedCookie(name string) bool {
	return name == g.sessions.CookieName() || name == g.flowName
}

// rewrite builds the outbound request: target URL, cleaned path, sanitised
// headers and the gateway-asserted identity.
func (g *Gateway) rewrite(pr *httputil.ProxyRequest, up *upstream) {
	st := stateFrom(pr.In.Context())
	pr.SetURL(up.target)
	p := st.path
	if st.route.StripPrefix && st.route.Match.PathPrefix != "/" {
		p = strings.TrimPrefix(p, strings.TrimSuffix(st.route.Match.PathPrefix, "/"))
		if p == "" || p[0] != '/' {
			p = "/" + p
		}
	}
	pr.Out.URL.Path = strings.TrimSuffix(up.target.Path, "/") + p
	pr.Out.URL.RawPath = ""
	pr.Out.Host = up.target.Host

	if g.cfg.TrustedProxy {
		pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
	}
	pr.SetXForwarded()

	for h := range pr.Out.Header {
		if strings.HasPrefix(h, HeaderPrefix) {
			pr.Out.Header.Del(h)
		}
	}
	if !st.route.ForwardToken {
		pr.Out.Header.Del("Authorization")
	}
	// Strip gateway cookies; keep the application's own cookies.
	if cs := pr.In.Cookies(); len(cs) > 0 {
		pr.Out.Header.Del("Cookie")
		var keep []string
		for _, c := range cs {
			if !g.reservedCookie(c.Name) {
				keep = append(keep, c.Name+"="+c.Value)
			}
		}
		if len(keep) > 0 {
			pr.Out.Header.Set("Cookie", strings.Join(keep, "; "))
		}
	}
	pr.Out.Header.Set(HeaderRequest, st.id)
	if id := st.identity; id != nil {
		pr.Out.Header.Set(HeaderUser, id.Subject)
		pr.Out.Header.Set(HeaderAuthn, id.Method)
		if id.Email != "" {
			pr.Out.Header.Set(HeaderEmail, id.Email)
		}
		if len(id.Groups) > 0 {
			pr.Out.Header.Set(HeaderGroups, strings.Join(id.Groups, ","))
		}
	}
}

// ---- helpers --------------------------------------------------------------

func writeError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	id := ""
	if st := stateFrom(r.Context()); st != nil {
		id = st.id
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "request_id": id})
}
