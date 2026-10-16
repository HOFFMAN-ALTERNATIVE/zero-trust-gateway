// Package jose is a minimal JWS signer and JWK encoder used by the mock
// issuer and the test-suite. Verification lives in package jwtverify.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

var b64 = base64.RawURLEncoding

// Key is a private signing key with its identifier and algorithm.
type Key struct {
	Kid  string
	Alg  string // RS256, ES256 or EdDSA
	Priv crypto.Signer
}

// JWK is the public representation of a key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// Generate creates a fresh key for alg.
func Generate(kid, alg string) (*Key, error) {
	var (
		priv crypto.Signer
		err  error
	)
	switch alg {
	case "RS256":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ES256":
		priv, err = ecdsa.GenerateKey(ecdsaCurve(), rand.Reader)
	case "EdDSA":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("jose: unsupported alg %q", alg)
	}
	if err != nil {
		return nil, err
	}
	return &Key{Kid: kid, Alg: alg, Priv: priv}, nil
}

// Public returns the JWK for k.
func (k *Key) Public() JWK {
	j := JWK{Kid: k.Kid, Use: "sig", Alg: k.Alg}
	switch pub := k.Priv.Public().(type) {
	case *rsa.PublicKey:
		j.Kty, j.N, j.E = "RSA", b64.EncodeToString(pub.N.Bytes()), b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		j.Kty, j.Crv = "EC", "P-256"
		j.X, j.Y = b64.EncodeToString(pad32(pub.X.Bytes())), b64.EncodeToString(pad32(pub.Y.Bytes()))
	case ed25519.PublicKey:
		j.Kty, j.Crv, j.X = "OKP", "Ed25519", b64.EncodeToString(pub)
	}
	return j
}

// Sign produces a compact JWS over claims with the given header overrides.
func (k *Key) Sign(claims any) (string, error) {
	return SignWithHeader(k, map[string]any{"alg": k.Alg, "kid": k.Kid, "typ": "JWT"}, claims)
}

// SignWithHeader allows tests to forge arbitrary headers.
func SignWithHeader(k *Key, hdr map[string]any, claims any) (string, error) {
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	var sig []byte
	switch p := k.Priv.(type) {
	case *rsa.PrivateKey:
		d := sha256.Sum256([]byte(signing))
		sig, err = rsa.SignPKCS1v15(rand.Reader, p, crypto.SHA256, d[:])
	case *ecdsa.PrivateKey:
		d := sha256.Sum256([]byte(signing))
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, p, d[:])
		if err == nil {
			sig = append(pad32(r.Bytes()), pad32(s.Bytes())...)
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(p, []byte(signing))
	default:
		err = errors.New("jose: unsupported key type")
	}
	if err != nil {
		return "", err
	}
	return signing + "." + b64.EncodeToString(sig), nil
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
