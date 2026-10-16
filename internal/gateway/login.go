package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/oidc"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/session"
)

// flowState is sealed into a short-lived cookie between /login and /callback,
// binding the browser to its own state, nonce and PKCE verifier.
type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Expires  int64  `json:"e"`
}

const flowTTL = 10 * time.Minute

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// safeReturn only allows local absolute paths, preventing open redirects
// (//evil.example, /\evil.example, https://evil.example).
func safeReturn(rd string) string {
	if rd == "" || rd[0] != '/' || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") ||
		strings.HasPrefix(rd, reservedPath) || strings.ContainsAny(rd, "\r\n") {
		return "/"
	}
	return rd
}

func (g *Gateway) login(w http.ResponseWriter, r *http.Request) {
	verifier, challenge := oidc.PKCE()
	fs := flowState{
		State: session.RandomID(), Nonce: session.RandomID(), Verifier: verifier,
		Return: safeReturn(r.URL.Query().Get("rd")), Expires: g.now().Add(flowTTL).Unix(),
	}
	v, err := g.sessions.Seal(fs)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: g.flowName, Value: v, Path: "/", HttpOnly: true, Secure: *g.cfg.Session.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(flowTTL.Seconds()),
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, g.oidc.AuthCodeURL(fs.State, fs.Nonce, challenge, r.URL.Query().Get("login_hint")), http.StatusFound)
}

func (g *Gateway) callback(w http.ResponseWriter, r *http.Request) {
	fail := func(reason string) {
		g.metrics.AuthnFailures.WithLabelValues(reason).Inc()
		g.log.Warn("oidc callback rejected", "reason", reason)
		writeError(w, r, http.StatusUnauthorized, "login failed: "+reason)
	}
	ck, err := r.Cookie(g.flowName)
	if err != nil {
		fail("missing_flow")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: g.flowName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: *g.cfg.Session.Secure})
	var fs flowState
	if err := g.sessions.Open(ck.Value, &fs); err != nil || g.now().Unix() > fs.Expires {
		fail("invalid_flow")
		return
	}
	q := r.URL.Query()
	if q.Get("error") != "" {
		fail("idp_error")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(fs.State)) != 1 {
		fail("state_mismatch")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	idToken, err := g.oidc.Exchange(ctx, q.Get("code"), fs.Verifier)
	if err != nil {
		g.log.Warn("token exchange failed", "err", err)
		fail("exchange_failed")
		return
	}
	claims, err := g.verifier.Verify(ctx, idToken, fs.Nonce)
	if err != nil {
		fail(authnReason(err))
		return
	}
	cookie, s, err := g.sessions.Issue(claims.Subject, claims.Email, claims.Groups, time.Time{})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	g.metrics.Sessions.Inc()
	g.log.Info("session issued", "sub", s.Subject, "sid", s.ID, "expires", time.Unix(s.Expires, 0).UTC())
	http.SetCookie(w, cookie)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, fs.Return, http.StatusFound)
}

func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, g.sessions.Clear())
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Gateway) whoami(w http.ResponseWriter, r *http.Request) {
	id, err := g.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ztg"`)
		writeError(w, r, http.StatusUnauthorized, "not authenticated")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"sub": id.Subject, "email": id.Email, "groups": id.Groups, "via": id.Method})
}
