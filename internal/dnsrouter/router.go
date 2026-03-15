package dnsrouter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/anonvector/slipgate/internal/config"
)

// Router is a pure Go DNS forwarder that routes queries by domain.
type Router struct {
	listenAddr   string
	routes       map[string]string // domain → backend address (host:port)
	verifyRoutes []verifyRoute     // HMAC verification routes
	defaultDst   string
	mu           sync.RWMutex
	conn         *net.UDPConn
}

// New creates a new DNS router.
func New(listenAddr string) *Router {
	return &Router{
		listenAddr: listenAddr,
		routes:     make(map[string]string),
	}
}

// AddRoute maps a domain to a backend address.
func (r *Router) AddRoute(domain, backend string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Normalize: ensure trailing dot
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	r.routes[strings.ToLower(domain)] = backend
}

// AddVerifyRoute registers a domain's public key and MTU for HMAC verification.
// When the router receives a _ck.<nonce>.<domain> TXT query, it responds
// with HMAC-SHA256(pubkey, nonce) and the MTU value.
func (r *Router) AddVerifyRoute(domain string, pubkey []byte, mtu int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	r.verifyRoutes = append(r.verifyRoutes, verifyRoute{
		domainLabels: strings.Split(domain, "."),
		pubkey:       pubkey,
		mtu:          mtu,
	})
}

// SetDefault sets the default backend for unmatched queries.
func (r *Router) SetDefault(backend string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultDst = backend
}

// ListenAndServe starts the DNS router.
func (r *Router) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen addr: %w", err)
	}

	r.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	defer r.conn.Close()

	log.Printf("DNS router listening on %s", r.listenAddr)

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}

		// Copy packet for goroutine
		packet := make([]byte, n)
		copy(packet, buf[:n])

		go r.handleQuery(packet, clientAddr)
	}
}

func (r *Router) handleQuery(packet []byte, clientAddr *net.UDPAddr) {
	// Check for HMAC verification query (nzv.* TXT) first
	if r.handleVerify(packet, clientAddr) {
		return
	}

	// Extract domain from DNS query
	domain := extractDomain(packet)
	if domain == "" {
		return
	}

	// Find matching backend
	r.mu.RLock()
	backend := r.findBackend(domain)
	r.mu.RUnlock()

	if backend == "" {
		log.Printf("no route for %s", domain)
		return
	}

	// Forward to backend
	resp, err := forward(packet, backend)
	if err != nil {
		log.Printf("forward to %s: %v", backend, err)
		return
	}

	// Send response back to client
	r.conn.WriteToUDP(resp, clientAddr)
}

func (r *Router) findBackend(domain string) string {
	domain = strings.ToLower(domain)
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Try exact match first
	if dst, ok := r.routes[domain]; ok {
		return dst
	}

	// Try suffix match (for subdomains)
	for routeDomain, dst := range r.routes {
		if strings.HasSuffix(domain, "."+routeDomain) || domain == routeDomain {
			return dst
		}
	}

	return r.defaultDst
}

func forward(packet []byte, backend string) ([]byte, error) {
	addr, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// Serve loads config and starts the DNS router.
func Serve(cfgInterface interface{}) error {
	cfg, ok := cfgInterface.(*config.Config)
	if !ok {
		return fmt.Errorf("invalid config type")
	}

	r := New(cfg.Listen.Address)

	for _, tunnel := range cfg.Tunnels {
		if !tunnel.Enabled || !tunnel.IsDNSTunnel() {
			continue
		}
		backend := fmt.Sprintf("127.0.0.1:%d", tunnel.Port)
		r.AddRoute(tunnel.Domain, backend)
		log.Printf("route: %s → %s", tunnel.Domain, backend)

		// Register HMAC verification
		switch tunnel.Transport {
		case config.TransportDNSTT:
			if tunnel.DNSTT != nil && tunnel.DNSTT.PublicKey != "" {
				pubkey, err := loadPubkey(tunnel.DNSTT.PublicKey)
				if err != nil {
					log.Printf("verify: skip %s: %v", tunnel.Tag, err)
					continue
				}
				mtu := tunnel.DNSTT.MTU
				if mtu == 0 {
					mtu = config.DefaultMTU
				}
				r.AddVerifyRoute(tunnel.Domain, pubkey, mtu)
				log.Printf("verify: %s (HMAC via pubkey, mtu=%d)", tunnel.Domain, mtu)
			}
		case config.TransportSlipstream:
			if tunnel.Slipstream != nil && tunnel.Slipstream.Cert != "" {
				hmacKey, err := certToHMACKey(tunnel.Slipstream.Cert)
				if err != nil {
					log.Printf("verify: skip %s: %v", tunnel.Tag, err)
					continue
				}
				r.AddVerifyRoute(tunnel.Domain, hmacKey, 0)
				log.Printf("verify: %s (HMAC via cert fingerprint)", tunnel.Domain)
			}
		}
	}

	if cfg.Route.Default != "" {
		defaultTunnel := cfg.GetTunnel(cfg.Route.Default)
		if defaultTunnel != nil && defaultTunnel.IsDNSTunnel() {
			r.SetDefault(fmt.Sprintf("127.0.0.1:%d", defaultTunnel.Port))
		}
	}

	return r.ListenAndServe()
}

// certToHMACKey derives a 32-byte HMAC key from a PEM certificate file
// by computing SHA-256 of the DER-encoded certificate.
func certToHMACKey(certPath string) ([]byte, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}
	hash := sha256.Sum256(block.Bytes)
	return hash[:], nil
}

// loadPubkey loads a hex-encoded public key. If the value looks like a file
// path, it reads the file; otherwise it decodes the hex string directly.
func loadPubkey(pubkeyOrPath string) ([]byte, error) {
	hexStr := pubkeyOrPath
	if _, err := os.Stat(pubkeyOrPath); err == nil {
		data, err := os.ReadFile(pubkeyOrPath)
		if err != nil {
			return nil, fmt.Errorf("read pubkey file: %w", err)
		}
		hexStr = strings.TrimSpace(string(data))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode pubkey hex: %w", err)
	}
	return b, nil
}
