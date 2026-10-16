// Package mockidp is a minimal OpenID Connect issuer for demos and tests.
//
// It implements discovery, JWKS, the authorization-code flow with PKCE (S256),
// key rotation and a dev-only token endpoint for CLI/API demos. It has no real
// authentication: the "login" page is a user picker. Never expose it publicly.
package mockidp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/jose"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/session"
)

// User is a demo identity.
type User struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Groups  []string `json:"groups"`
}

// DefaultUsers are the demo personas used across the README and tests.
var DefaultUsers = map[string]User{
	"alice": {Subject: "u-1001", Email: "alice@example.com", Name: "Alice (SRE, admin)", Groups: []string{"engineering", "admins"}},
	"bob":   {Subject: "u-1002", Email: "bob@example.com", Name: "Bob (developer)", Groups: []string{"engineering"}},
	"carol": {Subject: "u-1003", Email: "carol@example.org", Name: "Carol (finance, contractor)", Groups: []string{"finance"}},
}

type code struct {
	user        string
	redirectURI string
	challenge   string
	nonce       string
	expires     time.Time
}

// Options configures the issuer.
type Options struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Users        map[string]User
	TokenTTL     time.Duration
	Alg          string // RS256 (default), ES256 or EdDSA
	EnableDevAPI bool   // /dev/token and /rotate
}

// IDP is the mock issuer. It is an http.Handler.
type IDP struct {
	opts Options
	mux  *http.ServeMux

	mu    sync.Mutex
	keys  []*jose.Key // keys[0] signs; older keys are still published
	codes map[string]code
	gen   int
}

// New creates an issuer with one signing key.
func New(o Options) (*IDP, error) {
	if o.Users == nil {
		o.Users = DefaultUsers
	}
	if o.TokenTTL == 0 {
		o.TokenTTL = 5 * time.Minute
	}
	if o.Alg == "" {
		o.Alg = "RS256"
	}
	p := &IDP{opts: o, codes: map[string]code{}}
	if err := p.Rotate(); err != nil {
		return nil, err
	}
	p.mux = http.NewServeMux()
	p.mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	p.mux.HandleFunc("GET /jwks", p.jwks)
	p.mux.HandleFunc("GET /authorize", p.authorize)
	p.mux.HandleFunc("POST /token", p.token)
	p.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	if o.EnableDevAPI {
		p.mux.HandleFunc("GET /dev/token", p.devToken)
		p.mux.HandleFunc("POST /rotate", func(w http.ResponseWriter, _ *http.Request) {
			if err := p.Rotate(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]string{"kid": p.CurrentKid()})
		})
	}
	return p, nil
}

// SetIssuer updates the issuer URL (for httptest servers whose URL is known late).
func (p *IDP) SetIssuer(iss string) { p.mu.Lock(); p.opts.Issuer = iss; p.mu.Unlock() }

// AddRedirectURI allows an extra redirect URI.
func (p *IDP) AddRedirectURI(u string) {
	p.mu.Lock()
	p.opts.RedirectURIs = append(p.opts.RedirectURIs, u)
	p.mu.Unlock()
}

func (p *IDP) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.mux.ServeHTTP(w, r) }

// Rotate generates a new signing key; the previous key stays published so
// tokens signed with it remain verifiable until they expire.
func (p *IDP) Rotate() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gen++
	k, err := jose.Generate(fmt.Sprintf("key-%d", p.gen), p.opts.Alg)
	if err != nil {
		return err
	}
	p.keys = append([]*jose.Key{k}, p.keys...)
	if len(p.keys) > 2 {
		p.keys = p.keys[:2]
	}
	return nil
}

// CurrentKid is the kid of the active signing key.
func (p *IDP) CurrentKid() string { p.mu.Lock(); defer p.mu.Unlock(); return p.keys[0].Kid }

// Issue signs a token for a known user with optional extra claims.
func (p *IDP) Issue(user string, extra map[string]any) (string, error) {
	p.mu.Lock()
	u, ok := p.opts.Users[user]
	key, iss, aud, ttl := p.keys[0], p.opts.Issuer, p.opts.ClientID, p.opts.TokenTTL
	p.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("unknown user %q", user)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": iss, "aud": aud, "sub": u.Subject, "email": u.Email, "email_verified": true,
		"name": u.Name, "groups": u.Groups, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(ttl).Unix(),
		"jti": session.RandomID(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return key.Sign(claims)
}

func (p *IDP) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	iss := p.opts.Issuer
	p.mu.Unlock()
	writeJSON(w, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"jwks_uri":                              iss + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{p.opts.Alg},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "email", "groups"},
	})
}

func (p *IDP) jwks(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	set := struct {
		Keys []jose.JWK `json:"keys"`
	}{}
	for _, k := range p.keys {
		set.Keys = append(set.Keys, k.Public())
	}
	p.mu.Unlock()
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, set)
}

var pickerTmpl = template.Must(template.New("p").Parse(`<!doctype html><html><head><meta charset="utf-8">
<title>Mock IdP · sign in</title><style>
body{font:15px/1.5 ui-monospace,monospace;background:#05070d;color:#cfe;display:grid;place-items:center;min-height:100vh;margin:0}
main{border:1px solid #0ff4;padding:2rem 2.5rem;box-shadow:0 0 40px #0ff2}h1{font-size:1rem;letter-spacing:.2em;color:#0ff}
a{display:block;margin:.6rem 0;padding:.6rem 1rem;border:1px solid #0ff3;color:#cfe;text-decoration:none}a:hover{background:#0ff1}
small{color:#7aa}</style></head><body><main><h1>MOCK OIDC ISSUER</h1><p><small>Development only — pick an identity.</small></p>
{{range .}}<a href="{{.URL}}">{{.Name}}<br><small>{{.Email}} · groups: {{.Groups}}</small></a>{{end}}</main></body></html>`))

func (p *IDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	clientOK := q.Get("client_id") == p.opts.ClientID
	redirectOK := slices.Contains(p.opts.RedirectURIs, q.Get("redirect_uri"))
	p.mu.Unlock()
	switch {
	case !clientOK:
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	case !redirectOK:
		http.Error(w, "redirect_uri not registered", http.StatusBadRequest)
		return
	case q.Get("response_type") != "code":
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	case q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		http.Error(w, "PKCE S256 required", http.StatusBadRequest)
		return
	}
	user := q.Get("login_hint")
	if _, ok := p.opts.Users[user]; !ok {
		type item struct{ URL, Name, Email, Groups string }
		names := make([]string, 0, len(p.opts.Users))
		for n := range p.opts.Users {
			names = append(names, n)
		}
		sort.Strings(names)
		items := make([]item, 0, len(names))
		for _, n := range names {
			u := p.opts.Users[n]
			q2 := r.URL.Query()
			q2.Set("login_hint", n)
			items = append(items, item{URL: "?" + q2.Encode(), Name: u.Name, Email: u.Email, Groups: fmt.Sprint(u.Groups)})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pickerTmpl.Execute(w, items)
		return
	}
	c := session.RandomID()
	p.mu.Lock()
	p.codes[c] = code{user: user, redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), expires: time.Now().Add(time.Minute)}
	p.mu.Unlock()
	dst, _ := url.Parse(q.Get("redirect_uri"))
	dq := dst.Query()
	dq.Set("code", c)
	dq.Set("state", q.Get("state"))
	dst.RawQuery = dq.Encode()
	http.Redirect(w, r, dst.String(), http.StatusFound)
}

func (p *IDP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, "invalid_request")
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.opts.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(p.opts.ClientSecret)) != 1 {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthErr(w, "unsupported_grant_type")
		return
	}
	p.mu.Lock()
	c, found := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code")) // single use, even on failure
	p.mu.Unlock()
	if !found || time.Now().After(c.expires) || c.redirectURI != r.PostForm.Get("redirect_uri") {
		oauthErr(w, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
		oauthErr(w, "invalid_grant")
		return
	}
	extra := map[string]any{}
	if c.nonce != "" {
		extra["nonce"] = c.nonce
	}
	tok, err := p.Issue(c.user, extra)
	if err != nil {
		oauthErr(w, "server_error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"access_token": tok, "id_token": tok, "token_type": "Bearer", "expires_in": int(p.opts.TokenTTL.Seconds())})
}

func (p *IDP) devToken(w http.ResponseWriter, r *http.Request) {
	tok, err := p.Issue(r.URL.Query().Get("user"), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": int(p.opts.TokenTTL.Seconds())})
}

func oauthErr(w http.ResponseWriter, code string) {
	writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, v any) { writeJSONStatus(w, http.StatusOK, v) }

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
