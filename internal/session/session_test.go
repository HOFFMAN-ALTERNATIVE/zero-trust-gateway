package session_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/session"
)

func key(id string, b byte) session.Key {
	return session.Key{ID: id, Secret: bytes.Repeat([]byte{b}, 32)}
}

func mgr(t *testing.T, now *time.Time, keys ...session.Key) *session.Manager {
	t.Helper()
	m, err := session.New(session.Options{Keys: keys, TTL: 15 * time.Minute, Secure: true, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	now := time.Now()
	m := mgr(t, &now, key("k1", 1))
	c, s, err := m.Issue("u-1", "a@example.com", []string{"eng"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "__Host-ztg_session" || !c.Secure || !c.HttpOnly || c.Path != "/" {
		t.Fatalf("cookie attributes not hardened: %+v", c)
	}
	got, err := m.Verify(c.Value)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "u-1" || got.ID != s.ID || got.Groups[0] != "eng" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestExpiryAndNotAfter(t *testing.T) {
	now := time.Now()
	m := mgr(t, &now, key("k1", 1))
	c, _, _ := m.Issue("u-1", "", nil, now.Add(time.Minute))
	now = now.Add(2 * time.Minute)
	if _, err := m.Verify(c.Value); !errors.Is(err, session.ErrExpired) {
		t.Fatalf("session must not outlive notAfter, got %v", err)
	}
}

func TestTamperingIsRejected(t *testing.T) {
	now := time.Now()
	m := mgr(t, &now, key("k1", 1), key("k0", 2))
	c, _, _ := m.Issue("u-1", "", []string{"eng"}, time.Time{})
	parts := strings.Split(c.Value, ".")
	forgedPayload := mgrValue(t, mgr(t, &now, key("k1", 9)), parts) // same kid, attacker secret
	cases := map[string]string{
		"empty":         "",
		"garbage":       "x.y.z",
		"bad version":   "v2." + strings.Join(parts[1:], "."),
		"kid swapped":   strings.Join([]string{parts[0], "k0", parts[2], parts[3]}, "."),
		"unknown kid":   strings.Join([]string{parts[0], "zz", parts[2], parts[3]}, "."),
		"mac stripped":  strings.Join(parts[:3], ".") + ".",
		"forged secret": forgedPayload,
	}
	for name, v := range cases {
		if _, err := m.Verify(v); !errors.Is(err, session.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func mgrValue(t *testing.T, m *session.Manager, _ []string) string {
	t.Helper()
	c, _, err := m.Issue("admin", "", []string{"admins"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return c.Value
}

func TestKeyRotation(t *testing.T) {
	now := time.Now()
	old := mgr(t, &now, key("k1", 1))
	c, _, _ := old.Issue("u-1", "", nil, time.Time{})
	rotated := mgr(t, &now, key("k2", 2), key("k1", 1)) // new key signs, old still verifies
	if _, err := rotated.Verify(c.Value); err != nil {
		t.Fatalf("old cookie should verify during rotation: %v", err)
	}
	retired := mgr(t, &now, key("k2", 2))
	if _, err := retired.Verify(c.Value); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("cookie signed by retired key must be rejected")
	}
}

func TestOptionsValidation(t *testing.T) {
	bad := []session.Options{
		{},
		{Keys: []session.Key{{ID: "k", Secret: []byte("short")}}},
		{Keys: []session.Key{{ID: "a.b", Secret: bytes.Repeat([]byte{1}, 32)}}},
		{Keys: []session.Key{key("k", 1), key("k", 2)}},
	}
	for i, o := range bad {
		if _, err := session.New(o); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	m, err := session.New(session.Options{Keys: []session.Key{key("k", 1)}})
	if err != nil {
		t.Fatal(err)
	}
	if m.CookieName() != "ztg_session" || m.TTL() != 15*time.Minute {
		t.Fatalf("defaults: %s %s", m.CookieName(), m.TTL())
	}
	if c := m.Clear(); c.MaxAge != -1 {
		t.Fatal("clear cookie must expire immediately")
	}
}
