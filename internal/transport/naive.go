package transport

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/warp"
)

// createNaiveService creates the Caddyfile and systemd service for NaiveProxy.
func createNaiveService(tunnel *config.TunnelConfig, cfg *config.Config) error {
	if tunnel.Naive == nil {
		return fmt.Errorf("naive config is nil")
	}

	backend := cfg.GetBackend(tunnel.Backend)
	if backend == nil {
		return fmt.Errorf("backend %q not found", tunnel.Backend)
	}

	tunnelDir := config.TunnelDir(tunnel.Tag)
	caddyfilePath := filepath.Join(tunnelDir, "Caddyfile")

	// Build Caddyfile
	caddyfile := buildCaddyfile(tunnel)
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0644); err != nil {
		return fmt.Errorf("write Caddyfile: %w", err)
	}

	binPath := filepath.Join(config.DefaultBinDir, "caddy-naive")

	svcUser := "root"
	svcGroup := "root"
	var env []string

	// When WARP is enabled, run under a dedicated user so outbound
	// forward-proxy traffic gets routed through the WireGuard interface.
	if cfg.Warp.Enabled {
		svcUser = warp.NaiveUser
		svcGroup = config.SystemGroup

		// Caddy stores ACME certs and runtime state under XDG_DATA_HOME.
		dataDir := filepath.Join(tunnelDir, ".caddy")
		_ = os.MkdirAll(dataDir, 0750)
		_ = exec.Command("chown", "-R", svcUser+":"+svcGroup, tunnelDir).Run()
		env = append(env, "XDG_DATA_HOME="+dataDir)
	}

	unit := &service.Unit{
		Name:        service.TunnelServiceName(tunnel.Tag),
		Description: fmt.Sprintf("SlipGate NaiveProxy: %s", tunnel.Tag),
		ExecStart:   fmt.Sprintf("%s run --config %s --adapter caddyfile", binPath, caddyfilePath),
		User:        svcUser,
		Group:       svcGroup,
		After:       "network.target",
		Restart:     "always",
		WorkingDir:  tunnelDir,
		Environment: env,
	}

	if err := service.Create(unit); err != nil {
		return err
	}

	// Restart if already running (e.g. Caddyfile updated with new credentials)
	if _, err := service.Status(unit.Name); err == nil {
		return service.Restart(unit.Name)
	}
	return service.Start(unit.Name)
}

func buildCaddyfile(tunnel *config.TunnelConfig) string {
	naiveCfg := tunnel.Naive

	user := naiveCfg.User
	pass := naiveCfg.Password
	if user == "" {
		user = "slipgate"
	}
	if pass == "" {
		pass = "slipgate"
	}

	decoy := naiveCfg.DecoyURL
	if decoy == "" {
		decoy = config.RandomDecoyURL()
	}

	port := naiveCfg.Port
	if port == 0 {
		port = 443
	}

	return fmt.Sprintf(`{
  admin off
  log {
    output stdout
    level WARN
  }
}

:%d, %s {
  tls %s
  route {
    forward_proxy {
      basic_auth %s %s
      hide_ip
      hide_via
      probe_resistance
    }
    reverse_proxy %s {
      header_up Host {upstream_hostport}
    }
  }
}
`, port, tunnel.Domain, naiveCfg.Email, user, pass, decoy)
}
