package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/config"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/devca"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/gateway"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/mockidp"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/policy"
)

// syncBuffer collects audit lines from concurrent handlers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type echo struct {
	Service string            `json:"service"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Peer    string            `json:"peer"`
	TLS     uint16            `json:"tls"`
}

type env struct {
	gw      *gateway.Gateway
	gwURL   string
	idp     *mockidp.IDP
	audit   *syncBuffer
	hits    *atomic.Int32
	cfgPath string
}

const cfgTmpl = `
listen: ":0"
public_url: {{.GW}}
oidc:
  issuer: {{.IDP}}
  client_id: ztg
  client_secret_env: TEST_CLIENT_SECRET
  jwks_min_refresh: 1ms
session:
  secure: false
  keys_env: TEST_SESSION_KEYS
upstreams:
  app:   { url: "{{.App}}",   ca_file: "{{.Dir}}/ca.pem", cert_file: "{{.Dir}}/gateway.pem", key_file: "{{.Dir}}/gateway-key.pem" }
  admin: { url: "{{.Admin}}", ca_file: "{{.Dir}}/ca.pem", cert_file: "{{.Dir}}/gateway.pem", key_file: "{{.Dir}}/gateway-key.pem" }
  nocert: { url: "{{.App}}",  ca_file: "{{.Dir}}/ca.pem" }
  rogue: { url: "{{.App}}",   ca_file: "{{.Dir}}/ca.pem", cert_file: "{{.Dir}}/rogue.pem", key_file: "{{.Dir}}/rogue-key.pem" }
  untrusted: { url: "{{.App}}", cert_file: "{{.Dir}}/gateway.pem", key_file: "{{.Dir}}/gateway-key.pem" }
routes:
  - name: public
    match: { path_prefix: /public }
    upstream: app
    public: true
  - name: app
    match: { path_prefix: /app }
    upstream: app
    strip_prefix: true
    allow:
      - name: employees
        email_domains: [example.com]
  - name: admin
    match: { path_prefix: /admin, methods: [GET, POST] }
    upstream: admin
    allow:
      - { name: admins, groups: [admins] }
      - { name: eng-read, groups: [engineering], methods: [GET] }
  - name: nocert
    match: { path_prefix: /nocert }
    upstream: nocert
    allow: [ { authenticated: true } ]
  - name: rogue
    match: { path_prefix: /rogue }
    upstream: rogue
    allow: [ { authenticated: true } ]
  - name: untrusted
    match: { path_prefix: /untrusted }
    upstream: untrusted
    allow: [ { authenticated: true } ]
`

func startUpstream(t *testing.T, name string, ca *devca.CA, hits *atomic.Int32) string {
	t.Helper()
	leaf, err := ca.Issue(devca.Server, name, time.Hour, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := leaf.TLS()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/set-cookie" {
			w.Header().Add("Set-Cookie", "ztg_session=attacker; Path=/")
			w.Header().Add("Set-Cookie", "app_pref=dark; Path=/")
		}
		h := map[string]string{}
		for k := range r.Header {
			h[k] = r.Header.Get(k)
		}
		_ = json.NewEncoder(w).Encode(echo{Service: name, Path: r.URL.Path, Headers: h, Peer: r.TLS.PeerCertificates[0].Subject.CommonName, TLS: r.TLS.Version})
	}))
	srv.TLS = devca.ServerTLS(ca.Pool(), cert)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	ca, err := devca.New("test-root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.WriteCA(dir); err != nil {
		t.Fatal(err)
	}
	gwLeaf, _ := ca.Issue(devca.Client, "gateway", time.Hour)
	if err := gwLeaf.Write(dir, "gateway"); err != nil {
		t.Fatal(err)
	}
	rogueCA, _ := devca.New("rogue-root", time.Hour)
	rogueLeaf, _ := rogueCA.Issue(devca.Client, "gateway", time.Hour) // right name, wrong CA
	if err := rogueLeaf.Write(dir, "rogue"); err != nil {
		t.Fatal(err)
	}

	hits := &atomic.Int32{}
	appURL := startUpstream(t, "app", ca, hits)
	adminURL := startUpstream(t, "admin", ca, hits)

	idp, err := mockidp.New(mockidp.Options{ClientID: "ztg", ClientSecret: "test-secret", EnableDevAPI: true, Alg: "ES256"})
	if err != nil {
		t.Fatal(err)
	}
	idpSrv := httptest.NewServer(idp)
	t.Cleanup(idpSrv.Close)
	idp.SetIssuer(idpSrv.URL)

	gwSrv := httptest.NewUnstartedServer(nil)
	gwURL := "http://" + gwSrv.Listener.Addr().String()
	idp.AddRedirectURI(gwURL + "/_ztg/callback")

	var raw bytes.Buffer
	_ = template.Must(template.New("c").Parse(cfgTmpl)).Execute(&raw, map[string]string{
		"GW": gwURL, "IDP": idpSrv.URL, "App": appURL, "Admin": adminURL, "Dir": dir,
	})
	cfgPath := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(cfgPath, raw.Bytes(), 0o600)
	getenv := func(k string) string {
		return map[string]string{
			"TEST_CLIENT_SECRET": "test-secret",
			"TEST_SESSION_KEYS":  "k1:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		}[k]
	}
	cfg, err := config.Parse(raw.Bytes(), getenv)
	if err != nil {
		t.Fatal(err)
	}
	audit := &syncBuffer{}
	gw, err := gateway.New(context.Background(), cfg, gateway.Options{Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	gwSrv.Config.Handler = gw.Handler()
	gwSrv.Start()
	t.Cleanup(gwSrv.Close)
	return &env{gw: gw, gwURL: gwURL, idp: idp, audit: audit, hits: hits, cfgPath: cfgPath}
}

func (e *env) token(t *testing.T, user string) string {
	t.Helper()
	tok, err := e.idp.Issue(user, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (e *env) do(t *testing.T, method, path, token string, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.gwURL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Add(hdr[i], hdr[i+1])
	}
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func decode(t *testing.T, b []byte) echo {
	t.Helper()
	var e echo
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("not an upstream response: %s", b)
	}
	return e
}

func TestBearerAllowedOverMutualTLS(t *testing.T) {
	e := setup(t)
	resp, body := e.do(t, "GET", "/app/hello", e.token(t, "alice"))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	got := decode(t, body)
	if got.Service != "app" || got.Path != "/hello" {
		t.Fatalf("routing/strip_prefix wrong: %+v", got)
	}
	if got.Peer != "gateway" || got.TLS != 0x0304 {
		t.Fatalf("upstream must see the gateway client cert over TLS 1.3, got peer=%q tls=%x", got.Peer, got.TLS)
	}
	h := got.Headers
	if h["X-Auth-Request-User"] != "u-1001" || h["X-Auth-Request-Email"] != "alice@example.com" ||
		h["X-Auth-Request-Groups"] != "engineering,admins" || h["X-Auth-Request-Method"] != "bearer" {
		t.Fatalf("identity headers: %v", h)
	}
	if h["Authorization"] != "" {
		t.Fatal("bearer token must not be forwarded by default")
	}
	if h["X-Request-Id"] == "" || h["X-Request-Id"] != resp.Header.Get("X-Request-Id") {
		t.Fatal("request id must be propagated and echoed")
	}
}

func TestDenyByDefault(t *testing.T) {
	e := setup(t)
	alice, bob, carol := e.token(t, "alice"), e.token(t, "bob"), e.token(t, "carol")
	cases := []struct {
		name, method, path, tok string
		want                    int
	}{
		{"anonymous api", "GET", "/app/x", "", 401},
		{"public anonymous", "GET", "/public/status", "", 200},
		{"no route", "GET", "/unknown", alice, 404},
		{"wrong email domain", "GET", "/app/x", carol, 403},
		{"admin group", "POST", "/admin/users", alice, 200},
		{"eng read-only", "GET", "/admin/users", bob, 200},
		{"eng write denied", "POST", "/admin/users", bob, 403},
		{"method not on route", "DELETE", "/admin/users", alice, 405},
		{"garbage token", "GET", "/app/x", "garbage", 401},
		{"bad token on public route", "GET", "/public/status", "garbage", 401},
	}
	before := e.hits.Load()
	allowed := int32(0)
	for _, tc := range cases {
		resp, body := e.do(t, tc.method, tc.path, tc.tok)
		if resp.StatusCode != tc.want {
			t.Errorf("%s: got %d want %d: %s", tc.name, resp.StatusCode, tc.want, body)
		}
		if tc.want == 200 {
			allowed++
		}
		if tc.want == 401 && resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: 401 without WWW-Authenticate", tc.name)
		}
	}
	if got := e.hits.Load() - before; got != allowed {
		t.Fatalf("denied requests reached upstreams: %d upstream hits for %d allowed requests", got, allowed)
	}
}

func TestSpoofedIdentityIsStripped(t *testing.T) {
	e := setup(t)
	_, body := e.do(t, "GET", "/app/x", e.token(t, "bob"),
		"X-Auth-Request-User", "u-1001", "X-Auth-Request-Groups", "admins", "X-Auth-Request-Extra", "1",
		"Cookie", "ztg_session=forged; app_pref=dark")
	h := decode(t, body).Headers
	if h["X-Auth-Request-User"] != "u-1002" || h["X-Auth-Request-Groups"] != "engineering" || h["X-Auth-Request-Extra"] != "" {
		t.Fatalf("client-supplied identity headers leaked: %v", h)
	}
	if h["Cookie"] != "app_pref=dark" {
		t.Fatalf("gateway cookies must be stripped, app cookies kept: %q", h["Cookie"])
	}
}

func TestUpstreamCannotSetGatewayCookies(t *testing.T) {
	e := setup(t)
	resp, _ := e.do(t, "GET", "/app/set-cookie", e.token(t, "alice"))
	sc := strings.Join(resp.Header.Values("Set-Cookie"), "|")
	if strings.Contains(sc, "ztg_session") || !strings.Contains(sc, "app_pref=dark") {
		t.Fatalf("Set-Cookie filtering wrong: %q", sc)
	}
}

func TestAmbiguousPathsRejected(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/app%2F..%2Fadmin", "/app/%5c..%5cadmin", "/app/x%00"} {
		if resp, _ := e.do(t, "GET", p, e.token(t, "alice")); resp.StatusCode != 400 {
			t.Errorf("%s: want 400, got %d", p, resp.StatusCode)
		}
	}
	// Dot-segments are normalised before policy: /public/../admin is the admin route.
	resp, _ := e.do(t, "POST", "/public/../admin/users", e.token(t, "bob"))
	if resp.StatusCode == 200 {
		t.Fatal("dot-segment traversal from a public route reached the admin upstream")
	}
}

func TestMutualTLSFailuresAreBadGateway(t *testing.T) {
	e := setup(t)
	tok := e.token(t, "alice")
	for _, p := range []string{"/nocert/x", "/rogue/x", "/untrusted/x"} {
		resp, body := e.do(t, "GET", p, tok)
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("%s: want 502 (mTLS must fail), got %d: %s", p, resp.StatusCode, body)
		}
	}
	m := scrape(t, e)
	for _, u := range []string{"nocert", "rogue", "untrusted"} {
		if !strings.Contains(m, `ztg_upstream_errors_total{upstream="`+u+`"} 1`) {
			t.Errorf("missing upstream error metric for %s", u)
		}
	}
}

func TestBrowserLoginFlow(t *testing.T) {
	e := setup(t)
	// 1. An anonymous browser is redirected to the login endpoint.
	req, _ := http.NewRequest("GET", e.gwURL+"/app/dashboard?tab=1", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/_ztg/login?rd=%2Fapp%2Fdashboard%3Ftab%3D1" {
		t.Fatalf("want redirect to login, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 2. Full authorization-code + PKCE round trip (login_hint picks the persona).
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	resp, err = browser.Get(e.gwURL + "/_ztg/login?rd=" + url.QueryEscape("/app/dashboard?tab=1") + "&login_hint=bob")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login flow ended with %d: %s", resp.StatusCode, body)
	}
	got := decode(t, body)
	if got.Path != "/dashboard" || got.Headers["X-Auth-Request-Method"] != "session" || got.Headers["X-Auth-Request-User"] != "u-1002" {
		t.Fatalf("session-authenticated request wrong: %+v", got)
	}

	// 3. whoami reflects the session; policy is still enforced per request.
	resp, err = browser.Get(e.gwURL + "/_ztg/whoami")
	if err != nil {
		t.Fatal(err)
	}
	var who map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&who)
	resp.Body.Close()
	if who["email"] != "bob@example.com" || who["via"] != "session" {
		t.Fatalf("whoami: %v", who)
	}
	resp, _ = browser.Post(e.gwURL+"/admin/users", "text/plain", nil)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("session user must still be subject to policy, got %d", resp.StatusCode)
	}

	// 4. Logout clears the session.
	resp, _ = browser.Post(e.gwURL+"/_ztg/logout", "text/plain", nil)
	resp.Body.Close()
	resp, _ = browser.Get(e.gwURL + "/_ztg/whoami")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("after logout want 401, got %d", resp.StatusCode)
	}
	if !strings.Contains(scrape(t, e), "ztg_sessions_issued_total 1") {
		t.Fatal("session metric not incremented")
	}
}

func TestCallbackRejectsForgedState(t *testing.T) {
	e := setup(t)
	// No flow cookie at all (login CSRF / replayed callback).
	resp, _ := e.do(t, "GET", "/_ztg/callback?code=x&state=y", "")
	if resp.StatusCode != 401 {
		t.Fatalf("callback without flow cookie: %d", resp.StatusCode)
	}
	// Valid flow cookie, but attacker-chosen state.
	resp, _ = e.do(t, "GET", "/_ztg/login?login_hint=alice", "")
	flow := resp.Cookies()[0]
	resp, _ = e.do(t, "GET", "/_ztg/callback?code=x&state=attacker", "", "Cookie", flow.Name+"="+flow.Value)
	if resp.StatusCode != 401 {
		t.Fatalf("state mismatch must be rejected, got %d", resp.StatusCode)
	}
}

func TestOpenRedirectPrevented(t *testing.T) {
	e := setup(t)
	jar, _ := cookiejar.New(nil)
	var last string
	browser := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		last = r.URL.String()
		return nil
	}}
	for _, rd := range []string{"//evil.example/x", "https://evil.example", "/\\evil.example"} {
		resp, err := browser.Get(e.gwURL + "/_ztg/login?login_hint=alice&rd=" + url.QueryEscape(rd))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if !strings.HasPrefix(last, e.gwURL+"/") || strings.Contains(last, "evil") {
			t.Fatalf("rd=%q ended at %q", rd, last)
		}
	}
}

func TestSigningKeyRotation(t *testing.T) {
	e := setup(t)
	old := e.token(t, "alice")
	if resp, _ := e.do(t, "GET", "/app/x", old); resp.StatusCode != 200 {
		t.Fatal("baseline failed")
	}
	if err := e.idp.Rotate(); err != nil {
		t.Fatal(err)
	}
	fresh := e.token(t, "alice")
	if resp, b := e.do(t, "GET", "/app/x", fresh); resp.StatusCode != 200 {
		t.Fatalf("token signed with rotated key rejected: %d %s", resp.StatusCode, b)
	}
	if resp, _ := e.do(t, "GET", "/app/x", old); resp.StatusCode != 200 {
		t.Fatal("token signed with previous (still published) key rejected")
	}
	if !strings.Contains(scrape(t, e), `ztg_jwks_refresh_total{result="ok"} 2`) {
		t.Fatal("rotation should have triggered exactly one extra JWKS fetch")
	}
}

func TestExpiredTokenAndMetrics(t *testing.T) {
	e := setup(t)
	tok, _ := e.idp.Issue("alice", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	resp, _ := e.do(t, "GET", "/app/x", tok)
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("expired token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	m := scrape(t, e)
	for _, want := range []string{`ztg_authn_failures_total{reason="expired"} 1`, `ztg_requests_total{code="401",decision="deny",route="app"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestAuditLog(t *testing.T) {
	e := setup(t)
	e.do(t, "POST", "/admin/users", e.token(t, "bob"))
	e.do(t, "GET", "/admin/users", e.token(t, "bob"))
	// The audit record is written after the response completes; wait for it.
	for deadline := time.Now().Add(2 * time.Second); strings.Count(e.audit.String(), "\n") < 2 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(e.audit.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("audit line is not JSON: %q", line)
		}
		events = append(events, ev)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 audit events, got %d", len(events))
	}
	deny, allow := events[0], events[1]
	if deny["decision"] != "deny" || deny["status"] != 403.0 || deny["sub"] != "u-1002" || deny["route"] != "admin" || deny["log"] != "audit" {
		t.Fatalf("deny event: %v", deny)
	}
	if allow["decision"] != "allow" || allow["rule"] != "eng-read" || allow["upstream"] != "admin" || allow["request_id"] == "" {
		t.Fatalf("allow event: %v", allow)
	}
}

func TestHealthReadinessAndDrain(t *testing.T) {
	e := setup(t)
	admin := httptest.NewServer(e.gw.AdminHandler())
	defer admin.Close()
	status := func(p string) int {
		resp, err := http.Get(admin.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if status("/healthz") != 200 || status("/readyz") != 503 {
		t.Fatal("before JWKS warmup: healthy but not ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.gw.Warmup(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for status("/readyz") != 200 {
		if time.Now().After(deadline) {
			t.Fatal("never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.gw.Drain()
	if status("/readyz") != 503 || status("/healthz") != 200 {
		t.Fatal("draining: not ready, still alive")
	}
}

func TestPolicyHotReload(t *testing.T) {
	e := setup(t)
	bob := e.token(t, "bob")
	if resp, _ := e.do(t, "POST", "/admin/x", bob); resp.StatusCode != 403 {
		t.Fatal("baseline")
	}
	if err := e.gw.ReloadPolicy([]policy.Route{{Name: "broken", Match: policy.Match{PathPrefix: "/"}, Upstream: "app"}}); err == nil {
		t.Fatal("invalid policy must be rejected")
	}
	if resp, _ := e.do(t, "POST", "/admin/x", bob); resp.StatusCode != 403 {
		t.Fatal("rejected reload must keep the previous policy")
	}
	err := e.gw.ReloadPolicy([]policy.Route{{Name: "admin", Match: policy.Match{PathPrefix: "/admin"}, Upstream: "admin",
		Allow: []policy.Rule{{Groups: []string{"engineering"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.do(t, "POST", "/admin/x", bob); resp.StatusCode != 200 {
		t.Fatal("new policy not applied")
	}
	if resp, _ := e.do(t, "GET", "/app/x", bob); resp.StatusCode != 404 {
		t.Fatal("routes removed by reload must 404")
	}
}

func TestConcurrentTraffic(t *testing.T) {
	e := setup(t)
	toks := []string{e.token(t, "alice"), e.token(t, "bob"), e.token(t, "carol")}
	want := []int{200, 403, 403}
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k := i % 3
			req, _ := http.NewRequest("POST", e.gwURL+"/admin/x", nil)
			req.Header.Set("Authorization", "Bearer "+toks[k])
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				bad.Add(1)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != want[k] {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d concurrent requests got the wrong decision", bad.Load())
	}
}

func scrape(t *testing.T, e *env) string {
	t.Helper()
	rec := httptest.NewRecorder()
	e.gw.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}
