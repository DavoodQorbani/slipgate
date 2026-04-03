package dnsrouter

import (
	"os"

	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
)

const serviceName = "slipgate-dnsrouter"

// CreateRouterService creates and enables the systemd service for the DNS router.
func CreateRouterService() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	unit := &service.Unit{
		Name:        serviceName,
		Description: "SlipGate DNS Router",
		ExecStart:   execPath + " dnsrouter serve",
		User:        "root", // needs to bind port 53
		Group:       config.SystemGroup,
		After:       "network.target",
		Restart:     "always",
	}

	if err := service.Create(unit); err != nil {
		return err
	}
	return service.Start(serviceName)
}

// StartRouterService starts the DNS router service.
func StartRouterService() error {
	return service.Start(serviceName)
}

// StopRouterService stops the DNS router service.
func StopRouterService() error {
	return service.Stop(serviceName)
}

// RestartRouterService restarts the DNS router service.
func RestartRouterService() error {
	return service.Restart(serviceName)
}
