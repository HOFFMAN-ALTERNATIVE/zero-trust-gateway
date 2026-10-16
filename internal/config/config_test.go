package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/config"
)

const keys = "k2:" + "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=,k1:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const valid = `
public_url: https://gw.example.com
oidc:
  issuer: https://idp.example.com
  client_id: ztg
  client_secret_env: OIDC_SECRET
session:
  ttl: 10m
upstreams:
  app:
    url: https://app.internal:8443
    ca_file: /certs/ca.pem
    cert_file: /certs/gw.pem
    key_file: /certs/gw-key.pem
routes:
  - name: app
    match: { path_prefix: / }
    upstream: app
    allow:
      - authenticated: true
`

func TestParseValid(t *testing.T) {
	c, err := config.Parse([]byte(valid), env(map[string]string{"ZTG_SESSION_KEYS": keys, "OIDC_SECRET": "s3cret"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.AdminListen != ":9090" || c.OIDC.Audience != "ztg" || !*c.Session.Secure {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Session.TTL.Duration != 10*time.Minute || len(c.Session.Keys) != 2 || c.Session.Keys[0].ID != "k2" {
		t.Fatalf("session config wrong: %+v", c.Session)
	}
	if c.OIDC.ClientSecret != "s3cret" || c.Upstreams["app"].Timeout.Duration != 30*time.Second {
		t.Fatal("secret/env or upstream defaults wrong")
	}
}

func TestParseErrors(t *testing.T) {
	e := env(map[string]string{"ZTG_SESSION_KEYS": keys})
	cases := map[string]struct {
		yaml string
		env  func(string) string
		want string
	}{
		"unknown key":      {valid + "\nbogus: 1\n", e, "bogus"},
		"no session keys":  {valid, env(nil), "ZTG_SESSION_KEYS is empty"},
		"short key":        {valid, env(map[string]string{"ZTG_SESSION_KEYS": "k:c2hvcnQ="}), "shorter than 32"},
		"bad duration":     {strings.Replace(valid, "ttl: 10m", "ttl: ten", 1), e, "duration"},
		"plaintext":        {strings.Replace(valid, "https://app.internal", "http://app.internal", 1), e, "allow_plaintext"},
		"no public_url":    {strings.Replace(valid, "public_url: https://gw.example.com", "", 1), e, "public_url"},
		"policy error":     {strings.Replace(valid, "authenticated: true", "groups: []", 1), e, "no conditions"},
		"cert without key": {strings.Replace(valid, "    key_file: /certs/gw-key.pem\n", "", 1), e, "go together"},
	}
	for name, tc := range cases {
		_, err := config.Parse([]byte(tc.yaml), tc.env)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}
}

func TestParseSessionKeys(t *testing.T) {
	ks, err := config.ParseSessionKeys(" a:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY , ")
	if err != nil || len(ks) != 1 || ks[0].ID != "a" || len(ks[0].Secret) != 32 {
		t.Fatalf("got %v %v", ks, err)
	}
	if _, err := config.ParseSessionKeys("nocolon"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := config.ParseSessionKeys("a:!!!"); err == nil {
		t.Fatal("expected base64 error")
	}
}
