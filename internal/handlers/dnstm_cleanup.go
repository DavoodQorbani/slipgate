package handlers

import (
	"os"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/system"
)

const (
	dnstmConfigDir = "/etc/dnstm"
	dnstmUser      = "dnstm"
	dnstmBinary    = "/usr/local/bin/dnstm"
)

// dnstmInstalled checks if dnstm is present on the system.
func dnstmInstalled() bool {
	if _, err := os.Stat(dnstmConfigDir); err == nil {
		return true
	}
	if _, err := os.Stat(dnstmBinary); err == nil {
		return true
	}
	for _, svc := range listDnstmServices() {
		if service.Exists(svc) {
			return true
		}
	}
	return false
}

// listDnstmServices returns all dnstm-* service names found on disk.
func listDnstmServices() []string {
	entries, err := os.ReadDir("/etc/systemd/system")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "dnstm-") && strings.HasSuffix(name, ".service") {
			names = append(names, strings.TrimSuffix(name, ".service"))
		}
	}
	return names
}

// offerDnstmCleanup detects dnstm and offers to remove it.
// Returns true if dnstm was found and cleaned up.
func offerDnstmCleanup(out actions.OutputWriter, action string) (bool, error) {
	if !dnstmInstalled() {
		return false, nil
	}

	out.Warning("Detected existing dnstm installation")
	ok, err := prompt.Confirm("Remove dnstm? Its services may conflict with slipgate (port 53)")
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil
	}

	// Stop and remove all dnstm services
	for _, svcName := range listDnstmServices() {
		out.Info("Stopping " + svcName + "...")
		_ = service.Stop(svcName)
		_ = service.Remove(svcName)
	}

	// Stop legacy microsocks if running under dnstm
	_ = service.Stop("microsocks")
	_ = service.Remove("microsocks")

	// Remove config directory
	if err := os.RemoveAll(dnstmConfigDir); err != nil {
		out.Warning("Failed to remove dnstm config: " + err.Error())
	}

	// Remove dnstm binary
	os.Remove(dnstmBinary)

	// Remove dnstm system user
	_ = system.RemoveSpecificUser(dnstmUser)

	out.Success("dnstm removed")
	return true, nil
}
