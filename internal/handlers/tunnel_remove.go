package handlers

import (
	"fmt"
	"os"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/router"
	"github.com/anonvector/slipgate/internal/service"
)

func handleTunnelRemove(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	tag := ctx.GetArg("tag")

	if tag == "" {
		return actions.NewError(actions.TunnelRemove, "tunnel tag is required (use --all to remove all)", nil)
	}

	if tag == "--all" {
		return handleTunnelRemoveAll(ctx, cfg)
	}

	tunnel := cfg.GetTunnel(tag)
	if tunnel == nil {
		return actions.NewError(actions.TunnelRemove, fmt.Sprintf("tunnel %q not found", tag), nil)
	}

	// Confirm
	ok, err := prompt.Confirm(fmt.Sprintf("Remove tunnel %q? This will stop the service and delete all keys.", tag))
	if err != nil {
		return err
	}
	if !ok {
		ctx.Output.Info("Cancelled")
		return nil
	}

	removeSingleTunnel(ctx, cfg, tag)

	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.TunnelRemove, "failed to save config", err)
	}

	ctx.Output.Success(fmt.Sprintf("Tunnel %q removed", tag))
	return nil
}

func handleTunnelRemoveAll(ctx *actions.Context, cfg *config.Config) error {
	if len(cfg.Tunnels) == 0 {
		ctx.Output.Info("No tunnels to remove")
		return nil
	}

	ok, err := prompt.Confirm(fmt.Sprintf("Remove ALL %d tunnel(s)? This will stop all services and delete all keys.", len(cfg.Tunnels)))
	if err != nil {
		return err
	}
	if !ok {
		ctx.Output.Info("Cancelled")
		return nil
	}

	// Collect tags first since we'll be mutating the slice
	var tags []string
	for _, t := range cfg.Tunnels {
		tags = append(tags, t.Tag)
	}

	for _, tag := range tags {
		removeSingleTunnel(ctx, cfg, tag)
		ctx.Output.Success(fmt.Sprintf("Removed %q", tag))
	}

	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.TunnelRemove, "failed to save config", err)
	}

	ctx.Output.Success(fmt.Sprintf("All %d tunnel(s) removed", len(tags)))
	return nil
}

func removeSingleTunnel(ctx *actions.Context, cfg *config.Config, tag string) {
	// Stop and remove service
	svcName := service.TunnelServiceName(tag)
	_ = service.Stop(svcName)
	_ = service.Remove(svcName)

	// Remove from router
	_ = router.RemoveTunnel(cfg, tag)

	// Remove tunnel directory
	tunnelDir := config.TunnelDir(tag)
	if err := os.RemoveAll(tunnelDir); err != nil {
		ctx.Output.Warning(fmt.Sprintf("Failed to remove tunnel dir: %v", err))
	}

	// Remove from config
	cfg.RemoveTunnel(tag)
	if cfg.Route.Active == tag {
		cfg.Route.Active = ""
		if len(cfg.Tunnels) > 0 {
			cfg.Route.Active = cfg.Tunnels[0].Tag
		}
	}

	// Auto-switch to single mode when only one DNS tunnel remains
	if cfg.Route.Mode == "multi" {
		dnsTunnelCount := 0
		for _, t := range cfg.Tunnels {
			if t.IsDNSTunnel() && t.Enabled {
				dnsTunnelCount++
			}
		}
		if dnsTunnelCount <= 1 {
			cfg.Route.Mode = "single"
			ctx.Output.Info("Switched to single-tunnel mode")
		}
	}
}
