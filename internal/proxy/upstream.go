package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
)

// UpstreamConfig holds the parsed upstream proxy settings.
type UpstreamConfig struct {
	ProxyURL *url.URL
	Domains  []string
}

// ParseUpstreamConfig builds an UpstreamConfig from the fence config.
// Returns nil when no upstream proxy is configured.
func ParseUpstreamConfig(cfg *config.Config) *UpstreamConfig {
	if cfg == nil || cfg.Network.UpstreamProxy == "" || len(cfg.Network.UpstreamProxyDomains) == 0 {
		return nil
	}
	u, err := url.Parse(cfg.Network.UpstreamProxy)
	if err != nil {
		return nil
	}
	return &UpstreamConfig{
		ProxyURL: u,
		Domains:  cfg.Network.UpstreamProxyDomains,
	}
}

// ShouldProxy reports whether traffic to host should be routed through the
// upstream proxy.
func (u *UpstreamConfig) ShouldProxy(host string) bool {
	if u == nil || u.ProxyURL == nil {
		return false
	}
	for _, domain := range u.Domains {
		if config.MatchesDomain(host, domain) {
			return true
		}
	}
	return false
}

// dialViaHTTPProxy establishes a TCP connection to target through an HTTP
// CONNECT proxy. The returned net.Conn is ready for raw I/O (e.g. TLS
// handshake) after the proxy has confirmed the tunnel.
func dialViaHTTPProxy(proxyURL *url.URL, host string, port int, timeout time.Duration) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		defaultPort := "80"
		if proxyURL.Scheme == "https" {
			defaultPort = "443"
		}
		proxyAddr = net.JoinHostPort(proxyURL.Hostname(), defaultPort)
	}

	proxyConn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy %s: %w", proxyAddr, err)
	}

	// Wrap in TLS when the upstream proxy uses https.
	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(proxyConn, &tls.Config{
			ServerName: proxyURL.Hostname(),
		})
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = proxyConn.Close()
			return nil, fmt.Errorf("TLS handshake with upstream proxy: %w", err)
		}
		proxyConn = tlsConn
	}

	target := fmt.Sprintf("%s:%d", host, port)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("send CONNECT to upstream proxy: %w", err)
	}

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("read upstream proxy response: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT returned %d", resp.StatusCode)
	}

	// Wrap the connection so any bytes buffered by the bufio.Reader are not
	// lost when the caller starts reading from the conn directly.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: proxyConn, r: br}, nil
	}
	return proxyConn, nil
}

// bufferedConn wraps a net.Conn with a bufio.Reader so that data already
// buffered by the reader is drained before falling through to the underlying
// connection.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}
