// Package session issues and verifies short-lived, HMAC-signed session cookies.
//
// Format: v1.<kid>.<base64url(json payload)>.<base64url(HMAC-SHA256)>
// The MAC covers "v1.<kid>.<payload>", so the key id cannot be swapped.
// Multiple keys may be configured: the first one signs, all of them verify,
// which enables zero-downtime key rotation.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// Errors returned by Verify.
var (
	ErrInvalid = errors.New("session: invalid")
	ErrExpired = errors.New("session: expired")
)

// Key is a named HMAC secret (≥ 32 bytes).
type Key struct {
	ID     string
	Secret []byte
}

// Session is the identity carried by the cookie. Keep it small: browsers cap
// cookies at ~4 KiB, and the gateway re-checks policy on every request anyway.
type Session struct {
	ID      string   `json:"sid"`
	Subject string   `json:"sub"`
	Email   string   `json:"email,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Issued  int64    `json:"iat"`
	Expires int64    `json:"exp"`
}

// Manager signs and verifies session cookies.
type Manager struct {
	keys   []Key
	ttl    time.Duration
	secure bool
	name   string
	now    func() time.Time
}

// Options configures a Manager.
type Options struct {
	Keys   []Key
	TTL    time.Duration // default 15m
	Secure bool          // Secure + __Host- prefix; disable only for plain-HTTP local demos
	Now    func() time.Time
}

// New validates the keys and returns a Manager.
func New(o Options) (*Manager, error) {
	if len(o.Keys) == 0 {
		return nil, errors.New("session: at least one key required")
	}
	seen := map[string]bool{}
	for _, k := range o.Keys {
		if k.ID == "" || strings.Contains(k.ID, ".") {
			return nil, fmt.Errorf("session: invalid key id %q", k.ID)
		}
		if len(k.Secret) < 32 {
			return nil, fmt.Errorf("session: key %q shorter than 32 bytes", k.ID)
		}
		if seen[k.ID] {
			return nil, fmt.Errorf("session: duplicate key id %q", k.ID)
		}
		seen[k.ID] = true
	}
	if o.TTL == 0 {
		o.TTL = 15 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	name := "ztg_session"
	if o.Secure {
		name = "__Host-ztg_session"
	}
	return &Manager{keys: o.Keys, ttl: o.TTL, secure: o.Secure, name: name, now: o.Now}, nil
}

// CookieName is the session cookie name.
func (m *Manager) CookieName() string { return m.name }

// TTL is the session lifetime.
func (m *Manager) TTL() time.Duration { return m.ttl }

func mac(secret []byte, msg string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// Seal signs an arbitrary payload with the current key (also used for the
// short-lived OIDC flow-state cookie).
func (m *Manager) Seal(payload any) (string, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	k := m.keys[0]
	body := "v1." + k.ID + "." + b64.EncodeToString(pb)
	return body + "." + b64.EncodeToString(mac(k.Secret, body)), nil
}

// Open verifies a sealed value and decodes it into out.
func (m *Manager) Open(value string, out any) error {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return ErrInvalid
	}
	var key *Key
	for i := range m.keys {
		if m.keys[i].ID == parts[1] {
			key = &m.keys[i]
			break
		}
	}
	if key == nil {
		return ErrInvalid
	}
	sig, err := b64.DecodeString(parts[3])
	if err != nil {
		return ErrInvalid
	}
	body := strings.Join(parts[:3], ".")
	if !hmac.Equal(sig, mac(key.Secret, body)) {
		return ErrInvalid
	}
	pb, err := b64.DecodeString(parts[2])
	if err != nil {
		return ErrInvalid
	}
	if err := json.Unmarshal(pb, out); err != nil {
		return ErrInvalid
	}
	return nil
}

// Issue creates a session cookie for the identity. The lifetime is the
// configured TTL, never longer than notAfter (e.g. the ID token expiry).
func (m *Manager) Issue(subject, email string, groups []string, notAfter time.Time) (*http.Cookie, *Session, error) {
	now := m.now()
	exp := now.Add(m.ttl)
	if !notAfter.IsZero() && notAfter.Before(exp) {
		exp = notAfter
	}
	s := &Session{ID: RandomID(), Subject: subject, Email: email, Groups: groups, Issued: now.Unix(), Expires: exp.Unix()}
	v, err := m.Seal(s)
	if err != nil {
		return nil, nil, err
	}
	return &http.Cookie{
		Name: m.name, Value: v, Path: "/", HttpOnly: true, Secure: m.secure,
		SameSite: http.SameSiteLaxMode, Expires: exp, MaxAge: int(exp.Sub(now).Seconds()),
	}, s, nil
}

// Verify parses and validates a cookie value.
func (m *Manager) Verify(value string) (*Session, error) {
	var s Session
	if err := m.Open(value, &s); err != nil {
		return nil, err
	}
	if s.Subject == "" {
		return nil, ErrInvalid
	}
	if !m.now().Before(time.Unix(s.Expires, 0)) {
		return nil, ErrExpired
	}
	return &s, nil
}

// Clear returns a cookie that deletes the session.
func (m *Manager) Clear() *http.Cookie {
	return &http.Cookie{Name: m.name, Value: "", Path: "/", HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1}
}

// RandomID returns 128 bits of URL-safe randomness.
func RandomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}
