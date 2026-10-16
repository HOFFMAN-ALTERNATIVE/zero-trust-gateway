package devca_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/devca"
)

func parse(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIssueChainsAndUsages(t *testing.T) {
	ca, err := devca.New("test-root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := ca.Issue(devca.Server, "app", time.Hour, "localhost", "127.0.0.1")
	cli, _ := ca.Issue(devca.Client, "gateway", time.Hour)

	sc := parse(t, srv.CertPEM)
	if _, err := sc.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "app", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server cert: %v", err)
	}
	if len(sc.IPAddresses) != 1 || sc.DNSNames[1] != "localhost" {
		t.Fatalf("SANs: %v %v", sc.DNSNames, sc.IPAddresses)
	}
	cc := parse(t, cli.CertPEM)
	if _, err := cc.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("client cert must not be usable as a server cert")
	}
	if _, err := cc.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client cert: %v", err)
	}
	other, _ := devca.New("other", time.Hour)
	if _, err := cc.Verify(x509.VerifyOptions{Roots: other.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("must not chain to an unrelated CA")
	}
	if _, err := ca.Issue(devca.Server, "", time.Hour); err == nil {
		t.Fatal("empty name must fail")
	}
}

func TestMutualTLSHandshake(t *testing.T) {
	ca, _ := devca.New("root", time.Hour)
	srvLeaf, _ := ca.Issue(devca.Server, "app", time.Hour, "127.0.0.1")
	cliLeaf, _ := ca.Issue(devca.Client, "gateway", time.Hour)
	srvCert, _ := srvLeaf.TLS()
	cliCert, _ := cliLeaf.TLS()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	ts.TLS = devca.ServerTLS(ca.Pool(), srvCert)
	ts.StartTLS()
	defer ts.Close()

	client := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), Certificates: certs, MinVersion: tls.VersionTLS13}}}
	}
	resp, err := client(cliCert).Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "gateway" || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("peer=%q version=%x", b, resp.TLS.Version)
	}
	if resp, err := client().Get(ts.URL); err == nil {
		resp.Body.Close()
		t.Fatal("request without client certificate must fail")
	}
}

func TestWriteFiles(t *testing.T) {
	dir := t.TempDir()
	ca, _ := devca.New("root", time.Hour)
	leaf, _ := ca.Issue(devca.Client, "gw", time.Hour)
	if err := ca.WriteCA(dir); err != nil {
		t.Fatal(err)
	}
	if err := leaf.Write(dir, "gw"); err != nil {
		t.Fatal(err)
	}
	for f, mode := range map[string]os.FileMode{"ca.pem": 0o644, "ca-key.pem": 0o600, "gw.pem": 0o644, "gw-key.pem": 0o600} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s: mode %v want %v", f, st.Mode().Perm(), mode)
		}
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "gw.pem"), filepath.Join(dir, "gw-key.pem")); err != nil {
		t.Fatal(err)
	}
}
