// Package policy implements the per-route, deny-by-default authorization engine.
//
// Evaluation order for a request:
//
//  1. Route selection: host (exact, optional) + longest path-prefix match.
//     No route → deny (404). Unknown paths never reach an upstream.
//  2. Method gate: if the route lists methods, others are denied (405).
//  3. Public routes skip identity checks (still audited).
//  4. Deny rules: any matching rule denies, regardless of allow rules.
//  5. Allow rules: at least one must match. No allow rules → deny.
//
// A rule matches when ALL of its conditions match; within a condition the
// listed values are alternatives (any-of). A rule without conditions is a
// configuration error, so "allow everything" can never happen by accident;
// use `authenticated: true` to express it explicitly.
package policy

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"sort"
	"strings"
)

// Identity is the authenticated principal.
type Identity struct {
	Subject string
	Email   string
	Groups  []string
	Claims  map[string]any
	Method  string // "bearer" or "session"
}

// Rule is a conjunction of conditions.
type Rule struct {
	Name          string         `yaml:"name"`
	Authenticated bool           `yaml:"authenticated"`
	Subjects      []string       `yaml:"subjects"`
	Emails        []string       `yaml:"emails"`
	EmailDomains  []string       `yaml:"email_domains"`
	Groups        []string       `yaml:"groups"`
	Claims        map[string]any `yaml:"claims"`
	Methods       []string       `yaml:"methods"`
	PathPrefixes  []string       `yaml:"path_prefixes"`
}

// Match selects requests for a route.
type Match struct {
	Host       string   `yaml:"host"`
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
}

// Route binds a match to an upstream and its rules.
type Route struct {
	Name        string `yaml:"name"`
	Match       Match  `yaml:"match"`
	Upstream    string `yaml:"upstream"`
	StripPrefix bool   `yaml:"strip_prefix"`
	Public      bool   `yaml:"public"`
	// ForwardToken passes the caller's bearer token upstream (off by default:
	// upstreams should trust the gateway's identity headers + mTLS instead).
	ForwardToken bool   `yaml:"forward_token"`
	Allow        []Rule `yaml:"allow"`
	Deny         []Rule `yaml:"deny"`
}

// Decision is the outcome of an evaluation.
type Decision struct {
	Allow  bool
	Status int    // HTTP status to return when denied
	Route  *Route // nil when no route matched
	Rule   string // rule that allowed/denied
	Reason string
}

// Engine is an immutable, validated set of routes.
type Engine struct {
	routes []Route // sorted: host-specific first, then longest prefix
}

// New validates routes and builds an Engine.
func New(routes []Route, upstreams map[string]bool) (*Engine, error) {
	var errs []error
	names := map[string]bool{}
	for i := range routes {
		r := &routes[i]
		if r.Name == "" {
			errs = append(errs, fmt.Errorf("route #%d: name required", i))
			continue
		}
		if names[r.Name] {
			errs = append(errs, fmt.Errorf("route %q: duplicate name", r.Name))
		}
		names[r.Name] = true
		if !strings.HasPrefix(r.Match.PathPrefix, "/") {
			errs = append(errs, fmt.Errorf("route %q: path_prefix must start with /", r.Name))
		}
		if upstreams != nil && !upstreams[r.Upstream] {
			errs = append(errs, fmt.Errorf("route %q: unknown upstream %q", r.Name, r.Upstream))
		}
		if r.Public && (len(r.Allow) > 0 || len(r.Deny) > 0) {
			errs = append(errs, fmt.Errorf("route %q: public routes cannot have allow/deny rules", r.Name))
		}
		if !r.Public && len(r.Allow) == 0 {
			errs = append(errs, fmt.Errorf("route %q: no allow rules (deny-by-default would block everything; mark it public or add rules)", r.Name))
		}
		r.Match.Methods = upper(r.Match.Methods)
		for j := range r.Allow {
			r.Allow[j].Methods = upper(r.Allow[j].Methods)
			if err := r.Allow[j].validate(); err != nil {
				errs = append(errs, fmt.Errorf("route %q allow #%d: %w", r.Name, j, err))
			}
		}
		for j := range r.Deny {
			r.Deny[j].Methods = upper(r.Deny[j].Methods)
			if err := r.Deny[j].validate(); err != nil {
				errs = append(errs, fmt.Errorf("route %q deny #%d: %w", r.Name, j, err))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sorted := slices.Clone(routes)
	sort.SliceStable(sorted, func(i, j int) bool {
		hi, hj := sorted[i].Match.Host != "", sorted[j].Match.Host != ""
		if hi != hj {
			return hi
		}
		return len(sorted[i].Match.PathPrefix) > len(sorted[j].Match.PathPrefix)
	})
	return &Engine{routes: sorted}, nil
}

func upper(ms []string) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = strings.ToUpper(m)
	}
	return out
}

func (r *Rule) validate() error {
	if !r.Authenticated && len(r.Subjects) == 0 && len(r.Emails) == 0 && len(r.EmailDomains) == 0 &&
		len(r.Groups) == 0 && len(r.Claims) == 0 && len(r.Methods) == 0 && len(r.PathPrefixes) == 0 {
		return errors.New("rule has no conditions (use authenticated: true to allow any signed-in user)")
	}
	return nil
}

// Routes returns the routes in evaluation order.
func (e *Engine) Routes() []Route { return e.routes }

// prefixMatch matches whole path segments: /api matches /api and /api/x, not /apix.
func prefixMatch(p, prefix string) bool {
	if prefix == "/" {
		return true
	}
	prefix = strings.TrimSuffix(prefix, "/")
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// Route finds the route for a request. The path must already be cleaned.
func (e *Engine) Route(host, p string) *Route {
	host = strings.ToLower(stripPort(host))
	for i := range e.routes {
		r := &e.routes[i]
		if r.Match.Host != "" && !strings.EqualFold(r.Match.Host, host) {
			continue
		}
		if prefixMatch(p, r.Match.PathPrefix) {
			return r
		}
	}
	return nil
}

func stripPort(h string) string {
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

// CleanPath normalises a request path so policy and upstream see the same
// thing (defeats /admin/../ and //admin tricks).
func CleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean("/" + p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// Evaluate decides whether id (nil = anonymous) may perform method on p via route r.
func Evaluate(r *Route, id *Identity, method, p string) Decision {
	if r == nil {
		return Decision{Status: http.StatusNotFound, Reason: "no route"}
	}
	d := Decision{Route: r}
	if len(r.Match.Methods) > 0 && !slices.Contains(r.Match.Methods, method) {
		d.Status, d.Reason = http.StatusMethodNotAllowed, "method not allowed on route"
		return d
	}
	if r.Public {
		d.Allow, d.Reason = true, "public route"
		return d
	}
	if id == nil {
		d.Status, d.Reason = http.StatusUnauthorized, "authentication required"
		return d
	}
	for i, rule := range r.Deny {
		if rule.matches(id, method, p) {
			d.Status, d.Rule, d.Reason = http.StatusForbidden, ruleName(rule, "deny", i), "matched deny rule"
			return d
		}
	}
	for i, rule := range r.Allow {
		if rule.matches(id, method, p) {
			d.Allow, d.Rule, d.Reason = true, ruleName(rule, "allow", i), "matched allow rule"
			return d
		}
	}
	d.Status, d.Reason = http.StatusForbidden, "no allow rule matched"
	return d
}

func ruleName(r Rule, kind string, i int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("%s[%d]", kind, i)
}

func (r *Rule) matches(id *Identity, method, p string) bool {
	if len(r.Methods) > 0 && !slices.Contains(r.Methods, method) {
		return false
	}
	if len(r.PathPrefixes) > 0 && !slices.ContainsFunc(r.PathPrefixes, func(pp string) bool { return prefixMatch(p, pp) }) {
		return false
	}
	if len(r.Subjects) > 0 && !slices.Contains(r.Subjects, id.Subject) {
		return false
	}
	if len(r.Emails) > 0 && !slices.ContainsFunc(r.Emails, func(e string) bool { return strings.EqualFold(e, id.Email) }) {
		return false
	}
	if len(r.EmailDomains) > 0 && !slices.ContainsFunc(r.EmailDomains, func(d string) bool {
		return id.Email != "" && strings.HasSuffix(strings.ToLower(id.Email), "@"+strings.ToLower(d))
	}) {
		return false
	}
	if len(r.Groups) > 0 && !slices.ContainsFunc(r.Groups, func(g string) bool { return slices.Contains(id.Groups, g) }) {
		return false
	}
	for k, want := range r.Claims {
		if !claimMatches(id.Claims[k], want) {
			return false
		}
	}
	return true
}

// claimMatches compares a token claim with a policy value. A list in the policy
// means any-of; a list in the token matches if it contains the wanted value.
func claimMatches(got, want any) bool {
	if wl, ok := want.([]any); ok {
		return slices.ContainsFunc(wl, func(w any) bool { return claimMatches(got, w) })
	}
	if gl, ok := got.([]any); ok {
		return slices.ContainsFunc(gl, func(g any) bool { return scalarEq(g, want) })
	}
	return got != nil && scalarEq(got, want)
}

func scalarEq(a, b any) bool { return fmt.Sprint(a) == fmt.Sprint(b) }
