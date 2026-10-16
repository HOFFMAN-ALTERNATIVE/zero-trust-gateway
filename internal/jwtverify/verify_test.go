package jwtverify_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/jose"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/jwtverify"
)

const (
	iss = "https://issuer.test"
	aud = "ztg"
)

type jwksServer struct {
	*httptest.Server
	mu    sync.Mutex
	keys  []*jose.Key
	hits  atomic.Int32
	fail  atomic.Bool
	extra []jose.JWK
}

func newJWKS(t testing.TB, keys ...*jose.Key) *jwksServer {
	t.Helper()
	s := &jwksServer{keys: keys}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		if s.fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		s.mu.Lock()
		set := map[string]any{}
		var ks []jose.JWK
		for _, k := range s.keys {
			ks = append(ks, k.Public())
		}
		ks = append(ks, s.extra...)
		set["keys"] = ks
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) setKeys(keys ...*jose.Key) { s.mu.Lock(); s.keys = keys; s.mu.Unlock() }

func mustKey(t testing.TB, kid, alg string) *jose.Key {
	t.Helper()
	k, err := jose.Generate(kid, alg)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func claims(mut ...func(map[string]any)) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": iss, "aud": aud, "sub": "u-1", "email": "a@example.com", "groups": []string{"eng"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for _, m := range mut {
		m(c)
	}
	return c
}

func sign(t testing.TB, k *jose.Key, c map[string]any) string {
	t.Helper()
	tok, err := k.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func verifier(t testing.TB, url string, opts ...func(*jwtverify.Config, *jwtverify.KeySetOptions)) *jwtverify.Verifier {
	t.Helper()
	cfg := jwtverify.Config{Issuer: iss, Audience: aud}
	ko := jwtverify.KeySetOptions{MinRefresh: time.Nanosecond}
	for _, o := range opts {
		o(&cfg, &ko)
	}
	v, err := jwtverify.NewVerifier(cfg, jwtverify.NewKeySet(url, ko))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyAlgorithms(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			k := mustKey(t, "k-"+alg, alg)
			srv := newJWKS(t, k)
			v := verifier(t, srv.URL)
			c, err := v.Verify(context.Background(), sign(t, k, claims()), "")
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if c.Subject != "u-1" || c.Email != "a@example.com" || len(c.Groups) != 1 || c.Raw["sub"] != "u-1" {
				t.Fatalf("claims not decoded: %+v", c)
			}
		})
	}
}

func TestVerifyRejections(t *testing.T) {
	k := mustKey(t, "k1", "ES256")
	other := mustKey(t, "k1", "ES256") // same kid, different key: forged signature
	rsa := mustKey(t, "k-rsa", "RS256")
	srv := newJWKS(t, k, rsa)
	v := verifier(t, srv.URL, func(c *jwtverify.Config, _ *jwtverify.KeySetOptions) { c.Leeway = time.Second })

	good := sign(t, k, claims())
	parts := strings.Split(good, ".")
	none := mustNone(t, claims())

	hs, _ := jose.SignWithHeader(k, map[string]any{"alg": "HS256", "kid": "k1"}, claims())
	crit, _ := jose.SignWithHeader(k, map[string]any{"alg": "ES256", "kid": "k1", "crit": []string{"exp"}}, claims())
	noKid, _ := jose.SignWithHeader(k, map[string]any{"alg": "ES256"}, claims())
	// RSA key used with an ES256 header: algorithm/key-type confusion.
	confused, _ := jose.SignWithHeader(k, map[string]any{"alg": "ES256", "kid": "k-rsa"}, claims())

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"garbage", "not-a-jwt", jwtverify.ErrMalformed},
		{"too many segments", good + ".x", jwtverify.ErrMalformed},
		{"alg none", none, jwtverify.ErrAlgorithm},
		{"alg HS256", hs, jwtverify.ErrAlgorithm},
		{"crit header", crit, jwtverify.ErrMalformed},
		{"missing kid", noKid, jwtverify.ErrMalformed},
		{"key type confusion", confused, jwtverify.ErrAlgorithm},
		{"forged signature", sign(t, other, claims()), jwtverify.ErrSignature},
		{"payload swapped", parts[0] + "." + strings.Split(sign(t, k, claims(func(c map[string]any) { c["groups"] = []string{"admins"} })), ".")[1] + "." + parts[2], jwtverify.ErrSignature},
		{"unknown kid", sign(t, mustKey(t, "nope", "ES256"), claims()), jwtverify.ErrUnknownKey},
		{"expired", sign(t, k, claims(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() })), jwtverify.ErrExpired},
		{"no exp", sign(t, k, claims(func(c map[string]any) { delete(c, "exp") })), jwtverify.ErrMissingClaim},
		{"no sub", sign(t, k, claims(func(c map[string]any) { delete(c, "sub") })), jwtverify.ErrMissingClaim},
		{"nbf in future", sign(t, k, claims(func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() })), jwtverify.ErrNotYetValid},
		{"iat in future", sign(t, k, claims(func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() })), jwtverify.ErrNotYetValid},
		{"wrong issuer", sign(t, k, claims(func(c map[string]any) { c["iss"] = "https://evil.test" })), jwtverify.ErrIssuer},
		{"wrong audience", sign(t, k, claims(func(c map[string]any) { c["aud"] = "other" })), jwtverify.ErrAudience},
		{"oversized", strings.Repeat("a", 9000), jwtverify.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tc.token, "")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if jwtverify.Reason(err) == "other" {
				t.Fatalf("error %v has no metrics reason", err)
			}
		})
	}
}

func mustNone(t *testing.T, c map[string]any) string {
	t.Helper()
	k := mustKey(t, "k1", "ES256")
	tok, err := jose.SignWithHeader(k, map[string]any{"alg": "none", "kid": "k1"}, c)
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(tok, ".")
	return p[0] + "." + p[1] + "."
}

func TestAudienceArrayAndNonce(t *testing.T) {
	k := mustKey(t, "k1", "RS256")
	v := verifier(t, newJWKS(t, k).URL)
	tok := sign(t, k, claims(func(c map[string]any) { c["aud"] = []string{"other", aud}; c["nonce"] = "n-1" }))
	if _, err := v.Verify(context.Background(), tok, "n-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), tok, "n-2"); !errors.Is(err, jwtverify.ErrNonce) {
		t.Fatalf("want nonce error, got %v", err)
	}
}

func TestLeewayTolerance(t *testing.T) {
	k := mustKey(t, "k1", "ES256")
	v := verifier(t, newJWKS(t, k).URL, func(c *jwtverify.Config, _ *jwtverify.KeySetOptions) { c.Leeway = 30 * time.Second })
	tok := sign(t, k, claims(func(c map[string]any) { c["exp"] = time.Now().Add(-10 * time.Second).Unix() }))
	if _, err := v.Verify(context.Background(), tok, ""); err != nil {
		t.Fatalf("10s past exp within 30s leeway should pass: %v", err)
	}
}

func TestKeyRotationRefetchesOnUnknownKid(t *testing.T) {
	k1, k2 := mustKey(t, "k1", "ES256"), mustKey(t, "k2", "ES256")
	srv := newJWKS(t, k1)
	v := verifier(t, srv.URL)
	ctx := context.Background()
	if _, err := v.Verify(ctx, sign(t, k1, claims()), ""); err != nil {
		t.Fatal(err)
	}
	srv.setKeys(k2, k1) // issuer rotates, keeps publishing the old key
	if _, err := v.Verify(ctx, sign(t, k2, claims()), ""); err != nil {
		t.Fatalf("token from rotated key should verify after refetch: %v", err)
	}
	if _, err := v.Verify(ctx, sign(t, k1, claims()), ""); err != nil {
		t.Fatalf("old key still published, should verify: %v", err)
	}
	srv.setKeys(k2) // old key retired
	if err := v.KeySet().Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, sign(t, k1, claims()), ""); !errors.Is(err, jwtverify.ErrUnknownKey) {
		t.Fatalf("retired key must be rejected, got %v", err)
	}
}

func TestUnknownKidRefetchIsRateLimited(t *testing.T) {
	k := mustKey(t, "k1", "ES256")
	srv := newJWKS(t, k)
	v := verifier(t, srv.URL, func(_ *jwtverify.Config, o *jwtverify.KeySetOptions) { o.MinRefresh = time.Hour })
	ctx := context.Background()
	if _, err := v.Verify(ctx, sign(t, k, claims()), ""); err != nil {
		t.Fatal(err)
	}
	attacker := mustKey(t, "random", "ES256")
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.Verify(ctx, sign(t, attacker, claims()), "")
		}()
	}
	wg.Wait()
	if h := srv.hits.Load(); h != 1 {
		t.Fatalf("kid spraying caused %d JWKS fetches, want 1", h)
	}
}

func TestStaleIfError(t *testing.T) {
	k := mustKey(t, "k1", "ES256")
	srv := newJWKS(t, k)
	now := time.Now()
	clock := func() time.Time { return now }
	v := verifier(t, srv.URL, func(_ *jwtverify.Config, o *jwtverify.KeySetOptions) {
		o.MaxAge, o.MinRefresh, o.Now = time.Minute, time.Second, clock
	})
	ctx := context.Background()
	tok := sign(t, k, claims(func(c map[string]any) { c["exp"] = now.Add(time.Hour).Unix() }))
	if _, err := v.Verify(ctx, tok, ""); err != nil {
		t.Fatal(err)
	}
	srv.fail.Store(true)
	now = now.Add(10 * time.Minute) // cache expired, issuer down
	if _, err := v.Verify(ctx, tok, ""); err != nil {
		t.Fatalf("cached key should be served when issuer is down: %v", err)
	}
	if !v.KeySet().Ready() || v.KeySet().Len() != 1 {
		t.Fatal("keyset should stay ready with 1 key")
	}
}

func TestJWKSSkipsUnusableKeys(t *testing.T) {
	k := mustKey(t, "good", "ES256")
	srv := newJWKS(t, k)
	srv.extra = []jose.JWK{
		{Kty: "RSA", Kid: "tiny", N: "AQAB", E: "AQAB"},
		{Kty: "EC", Kid: "off-curve", Crv: "P-256", X: strings.Repeat("A", 43), Y: strings.Repeat("A", 43)},
		{Kty: "oct", Kid: "hmac"},
		{Kty: "EC", Kid: "enc", Use: "enc", Crv: "P-256", X: k.Public().X, Y: k.Public().Y},
	}
	v := verifier(t, srv.URL)
	if err := v.KeySet().Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := v.KeySet().Len(); n != 1 {
		t.Fatalf("want only the usable key cached, got %d", n)
	}
}

func TestNewVerifierValidation(t *testing.T) {
	ks := jwtverify.NewKeySet("http://unused", jwtverify.KeySetOptions{})
	if _, err := jwtverify.NewVerifier(jwtverify.Config{Audience: aud}, ks); err == nil {
		t.Fatal("missing issuer must fail")
	}
	if _, err := jwtverify.NewVerifier(jwtverify.Config{Issuer: iss, Audience: aud, Algorithms: []string{"HS256"}}, ks); err == nil {
		t.Fatal("HS256 must not be configurable")
	}
}
