package jwtverify_test

import (
	"context"
	"testing"
)

func BenchmarkVerify(b *testing.B) {
	for _, alg := range []string{"ES256", "RS256", "EdDSA"} {
		b.Run(alg, func(b *testing.B) {
			k := mustKey(b, "k", alg)
			srv := newJWKS(b, k)
			v := verifier(b, srv.URL)
			tok := sign(b, k, claims())
			ctx := context.Background()
			if _, err := v.Verify(ctx, tok, ""); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := v.Verify(ctx, tok, ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
