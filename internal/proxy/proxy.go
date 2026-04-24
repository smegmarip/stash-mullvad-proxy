package proxy

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"stash-mullvad-proxy/internal/router"
	"stash-mullvad-proxy/internal/wireguard"
)

type Proxy struct {
	router    *router.Router
	wgManager *wireguard.Manager
}

func New(r *router.Router, wg *wireguard.Manager) *Proxy {
	return &Proxy{router: r, wgManager: wg}
}

func (p *Proxy) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      p,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 0, // CONNECT tunnels can be long-lived
		IdleTimeout:  120 * time.Second,
	}
	log.Printf("proxy listening on %s", addr)
	return srv.ListenAndServe()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS proxy requests (CONNECT method).
// The domain comes from the CONNECT host, no SNI parsing needed.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := p.dialForHost(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

// handleHTTP forwards plain HTTP proxy requests.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "missing host in proxy request", http.StatusBadRequest)
		return
	}

	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	destConn, err := p.dialForHost(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return destConn, nil
		},
		DisableKeepAlives: true,
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHop(outReq.Header)

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		destConn.Close()
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// dialForHost resolves the domain, looks up routing, and dials through
// the appropriate WireGuard tunnel or directly.
func (p *Proxy) dialForHost(hostPort string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = "443"
	}

	tunnelID, matched := p.router.Match(host)
	if matched {
		tunnel := p.wgManager.GetActiveTunnel(tunnelID)
		if tunnel != nil {
			// Resolve DNS via system resolver first
			addrs, err := net.LookupHost(host)
			if err != nil {
				return nil, err
			}

			// Bind source to the tunnel's assigned IP so policy routing kicks in
			localAddr, _ := net.ResolveTCPAddr("tcp", tunnel.LocalIP+":0")
			dialer := &net.Dialer{
				LocalAddr: localAddr,
				Timeout:   30 * time.Second,
			}

			target := net.JoinHostPort(addrs[0], port)
			log.Printf("proxy: %s → tunnel %s (%s → %s)", host, tunnel.Name, tunnel.InterfaceName, target)
			return dialer.Dial("tcp", target)
		}
		log.Printf("proxy: tunnel %d for %s not active, falling through to direct", tunnelID, host)
	}

	log.Printf("proxy: %s → direct", host)
	return net.DialTimeout("tcp", net.JoinHostPort(host, port), 30*time.Second)
}

func transfer(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHop(h http.Header) {
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}
