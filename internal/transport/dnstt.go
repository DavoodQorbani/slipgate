package transport

import (
	"fmt"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/config"
)

// buildDNSTTExecStart builds the ExecStart command for dnstt-server.
//
//	dnstt-server -privkey-file KEY -mtu MTU DOMAIN LISTENADDR UPSTREAMADDR
func buildDNSTTExecStart(tunnel *config.TunnelConfig, cfg *config.Config) (string, error) {
	if tunnel.DNSTT == nil {
		return "", fmt.Errorf("dnstt config is nil")
	}

	backend := cfg.GetBackend(tunnel.Backend)
	if backend == nil {
		return "", fmt.Errorf("backend %q not found", tunnel.Backend)
	}

	binPath := filepath.Join(config.DefaultBinDir, "dnstt-server")

	listenAddr := fmt.Sprintf("0.0.0.0:%d", tunnel.Port)

	mtu := tunnel.DNSTT.MTU
	if mtu == 0 {
		mtu = config.DefaultMTU
	}

	return fmt.Sprintf("%s -privkey-file %s -mtu %d %s %s %s",
		binPath,
		tunnel.DNSTT.PrivateKey,
		mtu,
		tunnel.Domain,
		listenAddr,
		backend.Address,
	), nil
}
