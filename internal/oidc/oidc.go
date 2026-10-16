// Package oidc is the relying-party side of the OpenID Connect
// authorization-code flow with PKCE: discovery, authorization URL and code
// exchange. Token verification is delegated to package jwtverify.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Endpoints of an OpenID provider.
type Endpoints struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Discover fetches /.well-known/openid-configuration and checks that the
// advertised issuer is exactly the configured one (OIDC Discovery §4.3).
func Discover(ctx context.Context, hc *http.Client, issuer string) (*Endpoints, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: status %d", resp.StatusCode)
	}
	var e Endpoints
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&e); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if e.Issuer != issuer {
		return nil, fmt.Errorf("oidc discovery: issuer mismatch %q != %q", e.Issuer, issuer)
	}
	if e.AuthorizationEndpoint == "" || e.TokenEndpoint == "" || e.JWKSURI == "" {
		return nil, errors.New("oidc discovery: incomplete metadata")
	}
	return &e, nil
}

// Client performs the authorization-code flow.
type Client struct {
	Endpoints    Endpoints
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	HTTP         *http.Client
}

// PKCE returns a random code_verifier and its S256 code_challenge (RFC 7636).
func PKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthCodeURL builds the authorization request URL.
func (c *Client) AuthCodeURL(state, nonce, challenge, loginHint string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURI},
		"scope":                 {strings.Join(c.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	sep := "?"
	if strings.Contains(c.Endpoints.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return c.Endpoints.AuthorizationEndpoint + sep + q.Encode()
}

// Exchange redeems an authorization code for an ID token.
func (c *Client) Exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURI},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoints.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	if resp.StatusCode != http.StatusOK || body.Error != "" {
		return "", fmt.Errorf("token exchange: status %d %s", resp.StatusCode, body.Error)
	}
	if body.IDToken == "" {
		return "", errors.New("token exchange: no id_token in response")
	}
	return body.IDToken, nil
}
