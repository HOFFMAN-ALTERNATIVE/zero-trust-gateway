// Package config loads and validates the gateway's YAML configuration.
// Secrets are never read from the file: they come from environment variables.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/policy"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/session"
)

// OIDC configures the identity provider. Endpoints may be given explicitly
// (useful when the browser-facing and back-channel URLs differ, e.g. inside
// docker-compose); otherwise they are discovered from the issuer.
type OIDC struct {
	Issuer                string   `yaml:"issuer"`
	ClientID              string   `yaml:"client_id"`
	ClientSecretEnv       string   `yaml:"client_secret_env"`
	Audience              string   `yaml:"audience"`
	AuthorizationEndpoint string   `yaml:"authorization_endpoint"`
	TokenEndpoint         string   `yaml:"token_endpoint"`
	JWKSURI               string   `yaml:"jwks_uri"`
	Scopes                []string `yaml:"scopes"`
	Algorithms            []string `yaml:"algorithms"`
	Leeway                Duration `yaml:"leeway"`
	JWKSMinRefresh        Duration `yaml:"jwks_min_refresh"`

	ClientSecret string `yaml:"-"`
}

// Session configures the cookie.
type Session struct {
	TTL     Duration `yaml:"ttl"`
	Secure  *bool    `yaml:"secure"`
	KeysEnv string   `yaml:"keys_env"`

	Keys []session.Key `yaml:"-"`
}

// Upstream is a backend reached over (m)TLS.
type Upstream struct {
	URL        string   `yaml:"url"`
	CAFile     string   `yaml:"ca_file"`
	CertFile   string   `yaml:"cert_file"`
	KeyFile    string   `yaml:"key_file"`
	ServerName string   `yaml:"server_name"`
	Timeout    Duration `yaml:"timeout"`
	// AllowPlaintext permits http:// upstreams. Off by default: zero trust
	// means the hop behind the gateway is authenticated too.
	AllowPlaintext bool `yaml:"allow_plaintext"`
}

// Config is the full gateway configuration.
type Config struct {
	Listen       string              `yaml:"listen"`
	AdminListen  string              `yaml:"admin_listen"`
	PublicURL    string              `yaml:"public_url"`
	TrustedProxy bool                `yaml:"trusted_proxy"` // honour X-Forwarded-For from a fronting LB
	OIDC         OIDC                `yaml:"oidc"`
	Session      Session             `yaml:"session"`
	Upstreams    map[string]Upstream `yaml:"upstreams"`
	Routes       []policy.Route      `yaml:"routes"`
	ShutdownWait Duration            `yaml:"shutdown_timeout"`
}

// Duration is a time.Duration that unmarshals from "15m".
type Duration struct{ time.Duration }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	d.Duration = v
	return nil
}

// Load reads path, resolves secrets from env and validates everything.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied
	if err != nil {
		return nil, err
	}
	return Parse(raw, os.Getenv)
}

// Parse decodes YAML strictly (unknown keys are errors) and validates it.
func Parse(raw []byte, getenv func(string) string) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.defaults()
	if err := c.resolveSecrets(getenv); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.AdminListen == "" {
		c.AdminListen = ":9090"
	}
	if c.OIDC.Audience == "" {
		c.OIDC.Audience = c.OIDC.ClientID
	}
	if len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = []string{"openid", "email", "groups"}
	}
	if c.Session.TTL.Duration == 0 {
		c.Session.TTL.Duration = 15 * time.Minute
	}
	if c.Session.Secure == nil {
		t := true
		c.Session.Secure = &t
	}
	if c.Session.KeysEnv == "" {
		c.Session.KeysEnv = "ZTG_SESSION_KEYS"
	}
	if c.ShutdownWait.Duration == 0 {
		c.ShutdownWait.Duration = 20 * time.Second
	}
	for n, u := range c.Upstreams {
		if u.Timeout.Duration == 0 {
			u.Timeout.Duration = 30 * time.Second
		}
		c.Upstreams[n] = u
	}
}

// ParseSessionKeys parses "kid:base64secret,kid2:base64secret" (first signs).
func ParseSessionKeys(s string) ([]session.Key, error) {
	items := strings.Split(s, ",")
	keys := make([]session.Key, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, secret, ok := strings.Cut(item, ":")
		if !ok {
			return nil, fmt.Errorf("session key %q: want kid:base64", id)
		}
		b, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			if b, err = base64.RawURLEncoding.DecodeString(secret); err != nil {
				return nil, fmt.Errorf("session key %q: bad base64", id)
			}
		}
		keys = append(keys, session.Key{ID: id, Secret: b})
	}
	return keys, nil
}

func (c *Config) resolveSecrets(getenv func(string) string) error {
	if c.OIDC.ClientSecretEnv != "" {
		c.OIDC.ClientSecret = getenv(c.OIDC.ClientSecretEnv)
	}
	keys, err := ParseSessionKeys(getenv(c.Session.KeysEnv))
	if err != nil {
		return fmt.Errorf("config: %s: %w", c.Session.KeysEnv, err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("config: %s is empty (generate one with: echo k1:$(openssl rand -base64 32))", c.Session.KeysEnv)
	}
	c.Session.Keys = keys
	return nil
}

func (c *Config) validate() error {
	var errs []error
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
		errs = append(errs, errors.New("oidc.issuer and oidc.client_id are required"))
	}
	if c.PublicURL == "" {
		errs = append(errs, errors.New("public_url is required (used for the OIDC redirect_uri)"))
	} else if u, err := url.Parse(c.PublicURL); err != nil || u.Host == "" {
		errs = append(errs, fmt.Errorf("public_url %q is not an absolute URL", c.PublicURL))
	}
	if _, err := session.New(session.Options{Keys: c.Session.Keys}); err != nil {
		errs = append(errs, err)
	}
	if len(c.Upstreams) == 0 {
		errs = append(errs, errors.New("at least one upstream is required"))
	}
	for name, u := range c.Upstreams {
		pu, err := url.Parse(u.URL)
		if err != nil || pu.Host == "" {
			errs = append(errs, fmt.Errorf("upstream %q: invalid url", name))
			continue
		}
		switch pu.Scheme {
		case "https":
		case "http":
			if !u.AllowPlaintext {
				errs = append(errs, fmt.Errorf("upstream %q: plaintext http requires allow_plaintext: true", name))
			}
		default:
			errs = append(errs, fmt.Errorf("upstream %q: unsupported scheme %q", name, pu.Scheme))
		}
		if (u.CertFile == "") != (u.KeyFile == "") {
			errs = append(errs, fmt.Errorf("upstream %q: cert_file and key_file go together", name))
		}
	}
	ups := map[string]bool{}
	for n := range c.Upstreams {
		ups[n] = true
	}
	if _, err := policy.New(c.Routes, ups); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
