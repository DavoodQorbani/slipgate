package clientcfg

import (
	"encoding/base64"
	"fmt"
	"net"

	"github.com/anonvector/slipgate/internal/config"
)

// URIOptions controls URI generation.
type URIOptions struct {
	ClientMode string // "dnstt" or "noizdns" (DNSTT transport only)
	Username   string // override SOCKS/SSH username
	Password   string // override SOCKS/SSH password
}

// GenerateURI builds a slipnet:// URI from tunnel + backend config.
func GenerateURI(tunnel *config.TunnelConfig, backend *config.BackendConfig, cfg *config.Config, opts URIOptions) (string, error) {
	var fields [TotalFields]string

	// Defaults
	fields[FVersion] = "16"
	fields[FTunnelType] = GetTunnelType(tunnel.Transport, tunnel.Backend, opts.ClientMode)
	fields[FName] = tunnel.Tag
	fields[FDomain] = tunnel.Domain
	fields[FResolvers] = "" // user configures in app
	fields[FAuthMode] = "0"
	fields[FKeepAlive] = "5000"
	fields[FCongestionControl] = "bbr"
	fields[FTCPListenPort] = "1080"
	fields[FTCPListenHost] = "127.0.0.1"
	fields[FGSOEnabled] = "0"
	fields[FSSHEnabled] = "0"
	fields[FFwdDNSThroughSSH] = "0"
	fields[FSSHHost] = "127.0.0.1"
	fields[FUseServerDNS] = "0"
	fields[FDNSTransport] = "udp"
	fields[FSSHAuthType] = "password"
	fields[FDNSTTAuthoritative] = "0"
	fields[FNaivePort] = "443"
	fields[FIsLocked] = "0"
	fields[FExpirationDate] = "0"
	fields[FAllowSharing] = "0"

	// Transport-specific
	switch tunnel.Transport {
	case config.TransportDNSTT:
		if tunnel.DNSTT != nil {
			fields[FPublicKey] = tunnel.DNSTT.PublicKey
		}

	case config.TransportSlipstream:
		// Slipstream uses cert, no pubkey field needed

	case config.TransportNaive:
		if tunnel.Naive != nil {
			fields[FNaivePort] = fmt.Sprintf("%d", tunnel.Naive.Port)
			fields[FNaiveUser] = tunnel.Naive.User
			if tunnel.Naive.Password != "" {
				fields[FNaivePass] = base64.StdEncoding.EncodeToString([]byte(tunnel.Naive.Password))
			}
		}
	}

	// User credentials
	socksUser := ""
	socksPass := ""

	if opts.Username != "" {
		socksUser = opts.Username
		socksPass = opts.Password
	} else if backend != nil && backend.Type == config.BackendSOCKS && backend.SOCKS != nil {
		socksUser = backend.SOCKS.User
		socksPass = backend.SOCKS.Password
	}

	fields[FSOCKSUser] = socksUser
	fields[FSOCKSPass] = socksPass

	// SSH backend
	if tunnel.Backend == config.BackendSSH {
		fields[FSSHEnabled] = "1"
		if opts.Username != "" {
			fields[FSSHUser] = opts.Username
			fields[FSSHPass] = opts.Password
		}
		fields[FSSHPort] = "22"
	}

	// NaiveProxy credentials override
	if tunnel.Transport == config.TransportNaive && tunnel.Naive != nil {
		if tunnel.Naive.User != "" {
			fields[FNaiveUser] = tunnel.Naive.User
		}
		if tunnel.Naive.Password != "" {
			fields[FNaivePass] = base64.StdEncoding.EncodeToString([]byte(tunnel.Naive.Password))
		}
	}

	return Encode(fields), nil
}

func getServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
