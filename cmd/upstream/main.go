// Command upstream is a demo backend that only speaks mutual TLS and echoes
// the identity asserted by the gateway.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/devca"
)

func main() {
	name := flag.String("name", "app", "service name")
	listen := flag.String("listen", ":8443", "listen address")
	certFile := flag.String("cert", "certs/app.pem", "server certificate")
	keyFile := flag.String("key", "certs/app-key.pem", "server key")
	caFile := flag.String("ca", "certs/ca.pem", "CA that signs gateway client certs")
	allowCN := flag.String("allow-client", "gateway", "comma-separated client certificate names allowed to connect")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	tlsCfg := devca.ServerTLS(pool, cert)
	allowed := strings.Split(*allowCN, ",")
	// Authorise the peer, not just authenticate it: only the gateway may call us.
	tlsCfg.VerifyPeerCertificate = func(_ [][]byte, chains [][]*x509.Certificate) error {
		for _, ch := range chains {
			for _, a := range allowed {
				if len(ch) > 0 && ch[0].Subject.CommonName == a {
					return nil
				}
			}
		}
		return errNotAllowed
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		peer := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peer = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service":     *name,
			"method":      r.Method,
			"path":        r.URL.Path,
			"user":        r.Header.Get("X-Auth-Request-User"),
			"email":       r.Header.Get("X-Auth-Request-Email"),
			"groups":      r.Header.Get("X-Auth-Request-Groups"),
			"authn":       r.Header.Get("X-Auth-Request-Method"),
			"request_id":  r.Header.Get("X-Request-Id"),
			"mtls_peer":   peer,
			"tls_version": tls.VersionName(r.TLS.Version),
		})
	})
	srv := &http.Server{Addr: *listen, Handler: mux, TLSConfig: tlsCfg, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("upstream %s: mTLS on %s", *name, *listen)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

var errNotAllowed = errors.New("client certificate not authorised")
