// Package devca is a tiny development certificate authority: one ECDSA P-256
// root and short-lived leaf certificates for servers and clients. It exists so
// the demo and the tests exercise real mutual TLS — it is not a production PKI.
package devca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA is an in-memory certificate authority.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// Leaf is an issued certificate.
type Leaf struct {
	CertPEM []byte
	KeyPEM  []byte
}

// TLS returns the leaf as a tls.Certificate.
func (l *Leaf) TLS() (tls.Certificate, error) { return tls.X509KeyPair(l.CertPEM, l.KeyPEM) }

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)) }

// New creates a self-signed root valid for validity.
func New(commonName string, validity time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"zero-trust-gateway dev CA"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// Pool returns a CertPool containing only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Kind selects the extended key usage of a leaf.
type Kind int

// Leaf kinds.
const (
	Server Kind = iota
	Client
)

// Issue signs a leaf for name. Server leaves get DNS/IP SANs for name plus
// any extra hosts; client leaves carry the name as CN and a URI-free SAN.
func (ca *CA) Issue(kind Kind, name string, validity time.Duration, hosts ...string) (*Leaf, error) {
	if name == "" {
		return nil, errors.New("devca: name required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if kind == Server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, h := range append([]string{name}, hosts...) {
			if ip := net.ParseIP(h); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, h)
			}
		}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Leaf{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
	}, nil
}

// WriteCA writes ca.pem (0644) and ca-key.pem (0600) into dir.
func (ca *CA) WriteCA(dir string) error {
	kb, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), ca.CertPEM, 0o644); err != nil { //nolint:gosec // public cert
		return err
	}
	return os.WriteFile(filepath.Join(dir, "ca-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

// Write stores <name>.pem and <name>-key.pem (0600) in dir.
func (l *Leaf) Write(dir, name string) error {
	if err := os.WriteFile(filepath.Join(dir, name+".pem"), l.CertPEM, 0o644); err != nil { //nolint:gosec // public cert
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+"-key.pem"), l.KeyPEM, 0o600)
}

// ServerTLS builds a TLS 1.3 server config that requires client certificates
// signed by ca (the upstream side of mTLS).
func ServerTLS(ca *x509.CertPool, cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
}
