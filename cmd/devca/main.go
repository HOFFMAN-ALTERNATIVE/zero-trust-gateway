// Command devca generates a development CA plus server and client certificates
// for the docker-compose demo and local testing.
//
//	devca -out ./certs -servers app,admin -clients gateway -validity 168h
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/devca"
)

func main() {
	out := flag.String("out", "certs", "output directory")
	servers := flag.String("servers", "app,admin", "comma-separated server names (each also gets localhost/127.0.0.1 SANs)")
	clients := flag.String("clients", "gateway", "comma-separated client names")
	validity := flag.Duration("validity", 7*24*time.Hour, "leaf validity (keep it short)")
	caValidity := flag.Duration("ca-validity", 30*24*time.Hour, "CA validity")
	force := flag.Bool("force", false, "overwrite an existing CA")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o750); err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(*out + "/ca.pem"); err == nil && !*force {
		fmt.Println("devca: certificates already present, keeping them (use -force to regenerate)")
		return
	}
	ca, err := devca.New("ztg-dev-root", *caValidity)
	if err != nil {
		log.Fatal(err)
	}
	if err := ca.WriteCA(*out); err != nil {
		log.Fatal(err)
	}
	for _, s := range split(*servers) {
		leaf, err := ca.Issue(devca.Server, s, *validity, "localhost", "127.0.0.1")
		if err != nil {
			log.Fatal(err)
		}
		if err := leaf.Write(*out, s); err != nil {
			log.Fatal(err)
		}
	}
	for _, c := range split(*clients) {
		leaf, err := ca.Issue(devca.Client, c, *validity)
		if err != nil {
			log.Fatal(err)
		}
		if err := leaf.Write(*out, c); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("devca: wrote CA, servers=%s clients=%s to %s\n", *servers, *clients, *out)
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
