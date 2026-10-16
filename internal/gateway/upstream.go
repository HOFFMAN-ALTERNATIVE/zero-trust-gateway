package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/HOFFMAN-ALTERNATIVE/zero-trust-gateway/internal/config"
)

// certReloader serves the client certificate for mTLS and transparently picks
// up a renewed cert/key pair from disk (short-lived certs, no restart needed).
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	cr := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := cr.get(); err != nil {
		return nil, err
	}
	return cr, nil
}

func (c *certReloader) get() (*tls.Certificate, error) {
	st, err := os.Stat(c.certFile)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && st.ModTime().Equal(c.modTime) {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil // mid-rotation (cert written, key not yet): keep the old pair
		}
		return nil, err
	}
	c.cert, c.modTime = &cert, st.ModTime()
	return c.cert, nil
}

func (c *certReloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return c.get()
}

// upstream is one backend with its own hardened transport.
type upstream struct {
	name   string
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func newTransport(u config.Upstream) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: u.ServerName}
	if u.CAFile != "" {
		pem, err := os.ReadFile(u.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file: no certificates found")
		}
		tlsCfg.RootCAs = pool
	}
	if u.CertFile != "" {
		cr, err := newCertReloader(u.CertFile, u.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tlsCfg.GetClientCertificate = cr.GetClientCertificate
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 nil, // never route upstream traffic via env proxies
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: u.Timeout.Duration,
		ExpectContinueTimeout: time.Second,
	}, nil
}

func (g *Gateway) newUpstream(name string, u config.Upstream) (*upstream, error) {
	target, err := url.Parse(u.URL)
	if err != nil {
		return nil, err
	}
	tr, err := newTransport(u)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", name, err)
	}
	up := &upstream{name: name, target: target}
	up.proxy = &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1, // stream (SSE, chunked) without buffering
		Rewrite:       func(pr *httputil.ProxyRequest) { g.rewrite(pr, up) },
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.metrics.UpstreamErrors.WithLabelValues(name).Inc()
			if st := stateFrom(r.Context()); st != nil {
				st.upstreamErr = err
			}
			g.log.Warn("upstream error", "upstream", name, "err", err)
			writeError(w, r, http.StatusBadGateway, "upstream unavailable")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Upstreams must not be able to set or clobber the gateway's cookies.
			cookies := resp.Header.Values("Set-Cookie")
			resp.Header.Del("Set-Cookie")
			for _, c := range cookies {
				name, _, _ := strings.Cut(c, "=")
				if !g.reservedCookie(strings.TrimSpace(name)) {
					resp.Header.Add("Set-Cookie", c)
				}
			}
			return nil
		},
	}
	return up, nil
}
