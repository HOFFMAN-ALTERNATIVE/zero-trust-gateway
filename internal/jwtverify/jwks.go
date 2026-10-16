// Package jwtverify verifies OIDC / OAuth 2.0 JWTs against a remote JWKS.
//
// It is intentionally small and strict: an explicit algorithm allow-list
// (no "none", no HMAC with public keys), mandatory kid, issuer and audience
// pinning, bounded clock skew, and a JWKS cache that survives issuer outages
// and handles key rotation without hammering the issuer.
package jwtverify

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JWK is the subset of RFC 7517 fields this package understands.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet is a JSON Web Key Set document.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type parsedKey struct {
	alg string // optional pin from the JWK "alg" member
	key crypto.PublicKey
}

// ParseJWK converts a JWK into a Go public key. RSA keys under 2048 bits are rejected.
func ParseJWK(k JWK) (crypto.PublicKey, error) {
	b := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
	switch k.Kty {
	case "RSA":
		n, err := b(k.N)
		if err != nil {
			return nil, fmt.Errorf("rsa n: %w", err)
		}
		e, err := b(k.E)
		if err != nil {
			return nil, fmt.Errorf("rsa e: %w", err)
		}
		if len(e) == 0 || len(e) > 4 {
			return nil, errors.New("rsa e: invalid length")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("rsa key shorter than 2048 bits")
		}
		return pub, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := b(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b(k.Y)
		if err != nil {
			return nil, err
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("ec: bad coordinate length")
		}
		// Reject points that are not on the curve (invalid-curve attacks).
		uncompressed := append(append([]byte{4}, x...), y...)
		if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
			return nil, fmt.Errorf("ec: %w", err)
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := b(k.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("ed25519: bad key length")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

// KeySetOptions tunes the JWKS cache.
type KeySetOptions struct {
	// HTTPClient used to fetch the JWKS. Defaults to a client with a 5s timeout.
	HTTPClient *http.Client
	// MinRefresh bounds how often an unknown kid may trigger a refetch
	// (protects the issuer from kid-spraying). Default 30s.
	MinRefresh time.Duration
	// MaxAge is the cache lifetime when the issuer sends no Cache-Control. Default 10m.
	MaxAge time.Duration
	// Now is injectable for tests.
	Now func() time.Time
	// OnRefresh is called after each fetch attempt (for metrics).
	OnRefresh func(err error, keys int)
}

// KeySet is a concurrency-safe, self-refreshing JWKS cache.
type KeySet struct {
	url  string
	opts KeySetOptions

	mu        sync.RWMutex
	keys      map[string]parsedKey
	fetchedAt time.Time
	expiresAt time.Time
	lastTry   time.Time

	fetchMu sync.Mutex // serialises fetches (single-flight)
}

// NewKeySet creates a cache for the JWKS at url. Nothing is fetched until first use
// or an explicit Refresh.
func NewKeySet(url string, opts KeySetOptions) *KeySet {
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if opts.MinRefresh == 0 {
		opts.MinRefresh = 30 * time.Second
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = 10 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &KeySet{url: url, opts: opts, keys: map[string]parsedKey{}}
}

// Ready reports whether at least one successful fetch has happened.
func (s *KeySet) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.fetchedAt.IsZero()
}

// Len returns the number of cached keys.
func (s *KeySet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// Refresh fetches the JWKS now, honouring the single-flight lock but not MinRefresh.
func (s *KeySet) Refresh(ctx context.Context) error {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	return s.fetchLocked(ctx)
}

func (s *KeySet) fetchLocked(ctx context.Context) (err error) {
	now := s.opts.Now()
	s.mu.Lock()
	s.lastTry = now
	s.mu.Unlock()
	defer func() {
		if s.opts.OnRefresh != nil {
			s.opts.OnRefresh(err, s.Len())
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	var set JWKSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("jwks decode: %w", err)
	}
	keys := make(map[string]parsedKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pk, perr := ParseJWK(k)
		if perr != nil {
			continue // skip unusable keys, keep the rest
		}
		keys[k.Kid] = parsedKey{alg: k.Alg, key: pk}
	}
	if len(keys) == 0 {
		return errors.New("jwks: no usable signing keys")
	}
	s.mu.Lock()
	s.keys = keys
	s.fetchedAt = now
	s.expiresAt = now.Add(cacheTTL(resp.Header.Get("Cache-Control"), s.opts.MaxAge, s.opts.MinRefresh))
	s.mu.Unlock()
	return nil
}

// cacheTTL honours max-age, clamped to [minTTL, 24h].
func cacheTTL(cc string, def, minTTL time.Duration) time.Duration {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			if secs, err := strconv.Atoi(v); err == nil {
				d := time.Duration(secs) * time.Second
				return min(max(d, minTTL), 24*time.Hour)
			}
		}
	}
	return def
}

// key returns the key for kid, refreshing the cache when it is expired or
// when the kid is unknown (key rotation), rate-limited by MinRefresh.
// On fetch failure stale keys keep being served (stale-if-error).
func (s *KeySet) key(ctx context.Context, kid string) (parsedKey, error) {
	s.mu.RLock()
	k, ok := s.keys[kid]
	fresh := s.opts.Now().Before(s.expiresAt)
	s.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}

	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	// Re-check after acquiring the lock: another goroutine may have refreshed.
	s.mu.RLock()
	k, ok = s.keys[kid]
	fresh = s.opts.Now().Before(s.expiresAt)
	canFetch := s.lastTry.IsZero() || s.opts.Now().Sub(s.lastTry) >= s.opts.MinRefresh
	s.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	if canFetch {
		err := s.fetchLocked(ctx)
		s.mu.RLock()
		k, ok = s.keys[kid]
		s.mu.RUnlock()
		if ok {
			return k, nil // fresh, or stale-if-error
		}
		if err != nil {
			return parsedKey{}, fmt.Errorf("%w: %s: %w", ErrUnknownKey, kid, err)
		}
		return parsedKey{}, fmt.Errorf("%w: %s", ErrUnknownKey, kid)
	}
	if ok {
		return k, nil // expired but refetch is rate-limited: serve stale
	}
	return parsedKey{}, fmt.Errorf("%w: %s", ErrUnknownKey, kid)
}
