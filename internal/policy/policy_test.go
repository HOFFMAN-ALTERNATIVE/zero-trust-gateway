package policy_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/policy"
)

func engine(t testing.TB) *policy.Engine {
	t.Helper()
	e, err := policy.New([]policy.Route{
		{Name: "health", Match: policy.Match{PathPrefix: "/healthz"}, Upstream: "app", Public: true},
		{Name: "app", Match: policy.Match{PathPrefix: "/"}, Upstream: "app",
			Allow: []policy.Rule{{Name: "employees", EmailDomains: []string{"example.com"}}}},
		{Name: "admin", Match: policy.Match{PathPrefix: "/admin", Methods: []string{"get", "post", "delete"}}, Upstream: "admin",
			Deny:  []policy.Rule{{Name: "no-contractor-deletes", Methods: []string{"DELETE"}, Claims: map[string]any{"contractor": true}}},
			Allow: []policy.Rule{{Name: "admins", Groups: []string{"admins", "sre"}}, {Name: "readonly-eng", Groups: []string{"engineering"}, Methods: []string{"GET"}}}},
		{Name: "finance", Match: policy.Match{PathPrefix: "/finance/"}, Upstream: "app",
			Allow: []policy.Rule{{Claims: map[string]any{"department": []any{"finance", "audit"}, "email_verified": true}}}},
		{Name: "tenant", Match: policy.Match{Host: "tenant.example.com", PathPrefix: "/"}, Upstream: "app",
			Allow: []policy.Rule{{Authenticated: true}}},
	}, map[string]bool{"app": true, "admin": true})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func id(email string, groups []string, claims map[string]any) *policy.Identity {
	return &policy.Identity{Subject: "u", Email: email, Groups: groups, Claims: claims}
}

func TestRouteSelection(t *testing.T) {
	e := engine(t)
	cases := map[string]string{
		"/":              "app",
		"/healthz":       "health",
		"/admin":         "admin",
		"/admin/users":   "admin",
		"/administrator": "app", // segment match, not string prefix
		"/finance":       "finance",
		"/finance/q3":    "finance",
	}
	for p, want := range cases {
		if r := e.Route("gw.example.com:8080", p); r == nil || r.Name != want {
			t.Errorf("%s: got %v want %s", p, r, want)
		}
	}
	if r := e.Route("TENANT.example.com", "/admin"); r == nil || r.Name != "tenant" {
		t.Errorf("host routes take precedence, got %v", r)
	}
}

func TestEvaluate(t *testing.T) {
	e := engine(t)
	alice := id("alice@example.com", []string{"admins"}, map[string]any{})
	bob := id("bob@example.com", []string{"engineering"}, map[string]any{})
	contractor := id("c@example.com", []string{"admins"}, map[string]any{"contractor": true})
	carol := id("carol@example.org", nil, map[string]any{"department": "finance", "email_verified": true})
	unverified := id("dave@example.org", nil, map[string]any{"department": "finance", "email_verified": false})

	cases := []struct {
		name   string
		who    *policy.Identity
		method string
		path   string
		status int // 0 = allow
		rule   string
	}{
		{"public route anonymous", nil, "GET", "/healthz", 0, ""},
		{"anonymous is 401", nil, "GET", "/", http.StatusUnauthorized, ""},
		{"domain rule", bob, "GET", "/", 0, "employees"},
		{"wrong domain", carol, "GET", "/", http.StatusForbidden, ""},
		{"admin group", alice, "POST", "/admin/users", 0, "admins"},
		{"eng read-only GET", bob, "GET", "/admin", 0, "readonly-eng"},
		{"eng read-only POST denied", bob, "POST", "/admin", http.StatusForbidden, ""},
		{"route method gate", alice, "PUT", "/admin", http.StatusMethodNotAllowed, ""},
		{"deny beats allow", contractor, "DELETE", "/admin/x", http.StatusForbidden, "no-contractor-deletes"},
		{"contractor GET ok", contractor, "GET", "/admin/x", 0, "admins"},
		{"claim any-of", carol, "GET", "/finance/q3", 0, "allow[0]"},
		{"claim conjunction", unverified, "GET", "/finance/q3", http.StatusForbidden, ""},
		{"missing claim", bob, "GET", "/finance/q3", http.StatusForbidden, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.Route("gw", tc.path)
			d := policy.Evaluate(r, tc.who, tc.method, tc.path)
			if tc.status == 0 && !d.Allow {
				t.Fatalf("want allow, got deny %d (%s)", d.Status, d.Reason)
			}
			if tc.status != 0 && (d.Allow || d.Status != tc.status) {
				t.Fatalf("want %d, got allow=%v status=%d (%s)", tc.status, d.Allow, d.Status, d.Reason)
			}
			if tc.rule != "" && d.Rule != tc.rule {
				t.Fatalf("want rule %q, got %q", tc.rule, d.Rule)
			}
		})
	}
	if d := policy.Evaluate(nil, alice, "GET", "/x"); d.Allow || d.Status != http.StatusNotFound {
		t.Fatal("no route must be denied with 404")
	}
}

func TestTokenListClaims(t *testing.T) {
	e, err := policy.New([]policy.Route{{Name: "r", Match: policy.Match{PathPrefix: "/"}, Upstream: "u",
		Allow: []policy.Rule{{Claims: map[string]any{"roles": "editor"}}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := e.Route("h", "/")
	if !policy.Evaluate(r, id("", nil, map[string]any{"roles": []any{"viewer", "editor"}}), "GET", "/").Allow {
		t.Fatal("list claim containing the value should match")
	}
	if policy.Evaluate(r, id("", nil, map[string]any{"roles": []any{"viewer"}}), "GET", "/").Allow {
		t.Fatal("list claim without the value must not match")
	}
}

func TestValidation(t *testing.T) {
	ups := map[string]bool{"app": true}
	bad := map[string][]policy.Route{
		"empty rule":        {{Name: "r", Match: policy.Match{PathPrefix: "/"}, Upstream: "app", Allow: []policy.Rule{{}}}},
		"no allow rules":    {{Name: "r", Match: policy.Match{PathPrefix: "/"}, Upstream: "app"}},
		"public with rules": {{Name: "r", Match: policy.Match{PathPrefix: "/"}, Upstream: "app", Public: true, Allow: []policy.Rule{{Authenticated: true}}}},
		"unknown upstream":  {{Name: "r", Match: policy.Match{PathPrefix: "/"}, Upstream: "nope", Public: true}},
		"relative prefix":   {{Name: "r", Match: policy.Match{PathPrefix: "api"}, Upstream: "app", Public: true}},
		"duplicate":         {{Name: "r", Match: policy.Match{PathPrefix: "/"}, Upstream: "app", Public: true}, {Name: "r", Match: policy.Match{PathPrefix: "/a"}, Upstream: "app", Public: true}},
		"missing name":      {{Match: policy.Match{PathPrefix: "/"}, Upstream: "app", Public: true}},
	}
	for name, routes := range bad {
		if _, err := policy.New(routes, ups); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	_, err := policy.New([]policy.Route{
		{Name: "a", Match: policy.Match{PathPrefix: "/"}, Upstream: "x", Allow: []policy.Rule{{}}},
		{Name: "b", Match: policy.Match{PathPrefix: "/"}, Upstream: "y", Allow: []policy.Rule{{}}},
	}, ups)
	if err == nil || strings.Count(err.Error(), "\n") < 3 {
		t.Fatalf("all errors should be reported at once, got: %v", err)
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"":                 "/",
		"/":                "/",
		"/admin/../public": "/public",
		"//admin":          "/admin",
		"/a/./b/":          "/a/b/",
		"/../../etc":       "/etc",
	}
	for in, want := range cases {
		if got := policy.CleanPath(in); got != want {
			t.Errorf("CleanPath(%q)=%q want %q", in, got, want)
		}
	}
}
