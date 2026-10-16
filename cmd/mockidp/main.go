// Command mockidp runs the development OIDC issuer used by the demo.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/mockidp"
)

func main() {
	listen := flag.String("listen", ":9000", "listen address")
	issuer := flag.String("issuer", "http://localhost:9000", "issuer URL (as seen by browsers and in the iss claim)")
	clientID := flag.String("client-id", "ztg", "OAuth client id")
	redirects := flag.String("redirect-uris", "http://localhost:8080/_ztg/callback", "comma-separated allowed redirect URIs")
	alg := flag.String("alg", "RS256", "signing algorithm: RS256, ES256 or EdDSA")
	ttl := flag.Duration("token-ttl", 5*time.Minute, "token lifetime")
	flag.Parse()

	secret := os.Getenv("MOCKIDP_CLIENT_SECRET")
	if secret == "" {
		log.Fatal("MOCKIDP_CLIENT_SECRET must be set")
	}
	idp, err := mockidp.New(mockidp.Options{
		Issuer: *issuer, ClientID: *clientID, ClientSecret: secret,
		RedirectURIs: strings.Split(*redirects, ","), Alg: *alg, TokenTTL: *ttl, EnableDevAPI: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mockidp: issuer=%s alg=%s listening on %s (DEVELOPMENT ONLY)", *issuer, *alg, *listen)
	srv := &http.Server{Addr: *listen, Handler: idp, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
