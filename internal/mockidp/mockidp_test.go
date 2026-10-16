package mockidp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/mockidp"
	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/oidc"
)

func setup(t *testing.T) (*httptest.Server, *oidc.Client) {
	t.Helper()
	idp, err := mockidp.New(mockidp.Options{ClientID: "c", ClientSecret: "s", RedirectURIs: []string{"https://rp.test/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(idp)
	t.Cleanup(srv.Close)
	idp.SetIssuer(srv.URL)
	ep, err := oidc.Discover(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return srv, &oidc.Client{Endpoints: *ep, ClientID: "c", ClientSecret: "s", RedirectURI: "https://rp.test/cb", Scopes: []string{"openid"}, HTTP: srv.Client()}
}

// authorize runs the front-channel step and returns the issued code.
func authorize(t *testing.T, c *oidc.Client, challenge string) string {
	t.Helper()
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Get(c.AuthCodeURL("st", "nonce-1", challenge, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Host != "rp.test" || loc.Query().Get("state") != "st" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}
	return loc.Query().Get("code")
}

func TestCodeFlowWithPKCE(t *testing.T) {
	_, c := setup(t)
	verifier, challenge := oidc.PKCE()
	code := authorize(t, c, challenge)
	tok, err := c.Exchange(context.Background(), code, verifier)
	if err != nil || strings.Count(tok, ".") != 2 {
		t.Fatalf("exchange: %v", err)
	}
	if _, err := c.Exchange(context.Background(), code, verifier); err == nil {
		t.Fatal("authorization codes must be single-use")
	}
}

func TestWrongVerifierRejected(t *testing.T) {
	_, c := setup(t)
	_, challenge := oidc.PKCE()
	other, _ := oidc.PKCE()
	if _, err := c.Exchange(context.Background(), authorize(t, c, challenge), other); err == nil {
		t.Fatal("PKCE verifier mismatch must fail (intercepted code is useless)")
	}
}

func TestWrongClientSecretRejected(t *testing.T) {
	_, c := setup(t)
	v, ch := oidc.PKCE()
	code := authorize(t, c, ch)
	c.ClientSecret = "wrong"
	if _, err := c.Exchange(context.Background(), code, v); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("want invalid_client, got %v", err)
	}
}

func TestAuthorizeValidation(t *testing.T) {
	srv, c := setup(t)
	_, ch := oidc.PKCE()
	bad := []string{
		strings.Replace(c.AuthCodeURL("s", "n", ch, "alice"), "rp.test", "evil.test", 1),
		strings.Replace(c.AuthCodeURL("s", "n", ch, "alice"), "client_id=c", "client_id=x", 1),
		strings.Replace(c.AuthCodeURL("s", "n", ch, "alice"), "code_challenge_method=S256", "code_challenge_method=plain", 1),
	}
	for _, u := range bad {
		resp, err := srv.Client().Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("%s: want 400, got %d", u, resp.StatusCode)
		}
	}
	resp, _ := srv.Client().Get(c.AuthCodeURL("s", "n", ch, ""))
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatal("no login_hint should render the persona picker")
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	srv, _ := setup(t)
	if _, err := oidc.Discover(context.Background(), srv.Client(), srv.URL+"/"); err == nil {
		t.Fatal("issuer must match exactly")
	}
}
