package jwtverify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// Sentinel errors; callers use errors.Is and metrics use Reason.
var (
	ErrMalformed    = errors.New("malformed token")
	ErrAlgorithm    = errors.New("algorithm not allowed")
	ErrUnknownKey   = errors.New("unknown signing key")
	ErrSignature    = errors.New("invalid signature")
	ErrExpired      = errors.New("token expired")
	ErrNotYetValid  = errors.New("token not yet valid")
	ErrIssuer       = errors.New("issuer mismatch")
	ErrAudience     = errors.New("audience mismatch")
	ErrNonce        = errors.New("nonce mismatch")
	ErrMissingClaim = errors.New("required claim missing")
)

// Reason maps a verification error to a low-cardinality label.
func Reason(err error) string {
	for _, e := range []struct {
		err   error
		label string
	}{
		{ErrMalformed, "malformed"}, {ErrAlgorithm, "algorithm"}, {ErrUnknownKey, "unknown_key"},
		{ErrSignature, "signature"}, {ErrExpired, "expired"}, {ErrNotYetValid, "not_yet_valid"},
		{ErrIssuer, "issuer"}, {ErrAudience, "audience"}, {ErrNonce, "nonce"}, {ErrMissingClaim, "missing_claim"},
	} {
		if errors.Is(err, e.err) {
			return e.label
		}
	}
	return "other"
}

// Audience accepts both the string and array forms of "aud".
type Audience []string

// UnmarshalJSON implements json.Unmarshaler.
func (a *Audience) UnmarshalJSON(b []byte) error {
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("[")) {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*a = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*a = Audience{s}
	return nil
}

// Claims are the registered claims plus the identity claims the gateway uses.
// All claims are also kept in Raw for policy evaluation.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	Email     string   `json:"email,omitempty"`
	Groups    []string `json:"groups,omitempty"`

	Raw map[string]any `json:"-"`
}

// Config pins what a valid token must look like.
type Config struct {
	Issuer   string
	Audience string
	// Algorithms allowed; default RS256, ES256, EdDSA. HS* is never accepted.
	Algorithms []string
	// Leeway tolerated for exp/nbf/iat. Default 30s, capped at 5m.
	Leeway time.Duration
	// MaxTokenBytes defends against oversized headers. Default 8 KiB.
	MaxTokenBytes int
	Now           func() time.Time
}

// Verifier validates compact JWS tokens.
type Verifier struct {
	cfg  Config
	keys *KeySet
}

// NewVerifier builds a Verifier. Issuer and Audience are mandatory.
func NewVerifier(cfg Config, keys *KeySet) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("jwtverify: issuer and audience are required")
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"RS256", "ES256", "EdDSA"}
	}
	for _, a := range cfg.Algorithms {
		if !slices.Contains([]string{"RS256", "PS256", "ES256", "EdDSA"}, a) {
			return nil, fmt.Errorf("jwtverify: algorithm %q not supported", a)
		}
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	cfg.Leeway = min(cfg.Leeway, 5*time.Minute)
	if cfg.MaxTokenBytes == 0 {
		cfg.MaxTokenBytes = 8 << 10
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg, keys: keys}, nil
}

// KeySet exposes the underlying cache (for readiness checks).
func (v *Verifier) KeySet() *KeySet { return v.keys }

type header struct {
	Alg  string `json:"alg"`
	Kid  string `json:"kid"`
	Typ  string `json:"typ,omitempty"`
	Crit any    `json:"crit,omitempty"`
}

// Verify checks signature and claims. expectedNonce is checked when non-empty.
func (v *Verifier) Verify(ctx context.Context, token, expectedNonce string) (*Claims, error) {
	if len(token) > v.cfg.MaxTokenBytes {
		return nil, fmt.Errorf("%w: token too large", ErrMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments", ErrMalformed)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, fmt.Errorf("%w: header json", ErrMalformed)
	}
	if h.Crit != nil {
		return nil, fmt.Errorf("%w: crit not supported", ErrMalformed)
	}
	if !slices.Contains(v.cfg.Algorithms, h.Alg) {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, h.Alg)
	}
	if h.Kid == "" {
		return nil, fmt.Errorf("%w: kid required", ErrMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	pk, err := v.keys.key(ctx, h.Kid)
	if err != nil {
		return nil, err
	}
	if pk.alg != "" && pk.alg != h.Alg {
		return nil, fmt.Errorf("%w: key %s pinned to %s", ErrAlgorithm, h.Kid, pk.alg)
	}
	if err := verifySig(h.Alg, pk.key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrMalformed)
	}
	if err := json.Unmarshal(pb, &c.Raw); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrMalformed)
	}
	if err := v.validate(&c, expectedNonce); err != nil {
		return nil, err
	}
	return &c, nil
}

func (v *Verifier) validate(c *Claims, nonce string) error {
	now := v.cfg.Now()
	l := v.cfg.Leeway
	if c.Issuer != v.cfg.Issuer {
		return fmt.Errorf("%w: %q", ErrIssuer, c.Issuer)
	}
	if !slices.Contains(c.Audience, v.cfg.Audience) {
		return fmt.Errorf("%w: %v", ErrAudience, []string(c.Audience))
	}
	if c.Subject == "" {
		return fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	if c.Expiry == 0 {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	if !now.Before(time.Unix(c.Expiry, 0).Add(l)) {
		return ErrExpired
	}
	if c.NotBefore != 0 && now.Add(l).Before(time.Unix(c.NotBefore, 0)) {
		return ErrNotYetValid
	}
	if c.IssuedAt != 0 && now.Add(l).Before(time.Unix(c.IssuedAt, 0)) {
		return fmt.Errorf("%w: issued in the future", ErrNotYetValid)
	}
	if nonce != "" && c.Nonce != nonce {
		return ErrNonce
	}
	return nil
}

func verifySig(alg string, key crypto.PublicKey, signed, sig []byte) error {
	digest := sha256.Sum256(signed)
	switch alg {
	case "RS256", "PS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key type does not match %s", ErrAlgorithm, alg)
		}
		var err error
		if alg == "RS256" {
			err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
		} else {
			err = rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if err != nil {
			return ErrSignature
		}
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key type does not match %s", ErrAlgorithm, alg)
		}
		if len(sig) != 64 {
			return ErrSignature
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return ErrSignature
		}
	case "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key type does not match %s", ErrAlgorithm, alg)
		}
		if !ed25519.Verify(pub, signed, sig) {
			return ErrSignature
		}
	default:
		return fmt.Errorf("%w: %q", ErrAlgorithm, alg)
	}
	return nil
}
