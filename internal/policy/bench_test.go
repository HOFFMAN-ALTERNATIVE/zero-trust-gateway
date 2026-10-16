package policy_test

import (
	"testing"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/policy"
)

func BenchmarkRouteAndEvaluate(b *testing.B) {
	e := engine(b)
	who := id("bob@example.com", []string{"engineering"}, map[string]any{})
	b.ReportAllocs()
	for range b.N {
		r := e.Route("gw.example.com", "/admin/users/42")
		if d := policy.Evaluate(r, who, "GET", "/admin/users/42"); !d.Allow {
			b.Fatal(d.Reason)
		}
	}
}
