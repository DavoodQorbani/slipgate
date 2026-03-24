package network

import (
	"fmt"
	"os"
	"os/exec"
)

// AllowPort opens a port using the first available firewall tool.
func AllowPort(port int, proto string) error {
	// Try UFW first
	if _, err := exec.LookPath("ufw"); err == nil {
		return ufwAllow(port, proto)
	}

	// Try firewall-cmd
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		return firewalldAllow(port, proto)
	}

	// Fallback to iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		return iptablesAllow(port, proto)
	}

	return fmt.Errorf("no supported firewall found (ufw, firewalld, iptables)")
}

// RemovePort removes a firewall rule for a port.
func RemovePort(port int, proto string) error {
	if _, err := exec.LookPath("ufw"); err == nil {
		return run("ufw", "delete", "allow", fmt.Sprintf("%d/%s", port, proto))
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		_ = run("firewall-cmd", "--permanent", "--remove-port", fmt.Sprintf("%d/%s", port, proto))
		return run("firewall-cmd", "--reload")
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return run("iptables", "-D", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	}
	return nil
}

func ufwAllow(port int, proto string) error {
	return run("ufw", "allow", fmt.Sprintf("%d/%s", port, proto))
}

func firewalldAllow(port int, proto string) error {
	if err := run("firewall-cmd", "--permanent", "--add-port", fmt.Sprintf("%d/%s", port, proto)); err != nil {
		return err
	}
	return run("firewall-cmd", "--reload")
}

func iptablesAllow(port int, proto string) error {
	return run("iptables", "-A", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
}

// DisableResolvedStub disables systemd-resolved's DNS stub listener on port 53
// so that slipgate's DNS router can bind to it.
func DisableResolvedStub() error {
	// Check if systemd-resolved is running
	if err := exec.Command("systemctl", "is-active", "systemd-resolved").Run(); err != nil {
		return nil // not running, nothing to do
	}

	// Create drop-in config to disable stub listener
	if err := os.MkdirAll("/etc/systemd/resolved.conf.d", 0755); err != nil {
		return fmt.Errorf("create resolved conf dir: %w", err)
	}

	conf := "[Resolve]\nDNSStubListener=no\n"
	if err := os.WriteFile("/etc/systemd/resolved.conf.d/slipgate-no-stub.conf", []byte(conf), 0644); err != nil {
		return fmt.Errorf("write resolved config: %w", err)
	}

	// Restart systemd-resolved
	if err := run("systemctl", "restart", "systemd-resolved"); err != nil {
		return fmt.Errorf("restart systemd-resolved: %w", err)
	}

	// Fix /etc/resolv.conf to use real DNS (not the stub)
	_ = os.WriteFile("/etc/resolv.conf", []byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n"), 0644)

	return nil
}

// FreePort kills any process listening on the given port/protocol.
// Uses fuser if available, falls back to lsof + kill.
func FreePort(port int, proto string) error {
	if _, err := exec.LookPath("fuser"); err == nil {
		// fuser -k sends SIGKILL to all processes using the port
		protoFlag := fmt.Sprintf("%d/%s", port, proto)
		_ = exec.Command("fuser", "-k", protoFlag).Run()
		return nil
	}

	// Fallback: ss to find PIDs, then kill
	out, err := exec.Command("ss", "-tlnp", fmt.Sprintf("sport = :%d", port)).Output()
	if err != nil {
		return nil // can't determine, skip
	}
	// Parse PIDs from ss output (format: pid=1234)
	for _, line := range splitLines(string(out)) {
		for _, field := range splitFields(line) {
			if len(field) > 4 && field[:4] == "pid=" {
				pid := field[4:]
				// strip trailing comma or paren
				for len(pid) > 0 && (pid[len(pid)-1] == ',' || pid[len(pid)-1] == ')') {
					pid = pid[:len(pid)-1]
				}
				_ = exec.Command("kill", "-9", pid).Run()
			}
		}
	}
	return nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitFields(s string) []string {
	var fields []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if start < i {
			fields = append(fields, s[start:i])
		}
	}
	return fields
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}
