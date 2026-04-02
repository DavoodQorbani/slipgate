package handlers

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/version"
	"golang.org/x/term"
)

var sparkRunes = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

const graphWidth = 40

func handleSystemStats(ctx *actions.Context) error {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("cannot enter raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	fmt.Print("\033[?25l")                    // hide cursor
	defer fmt.Print("\033[?25h\033[H\033[2J") // show cursor + clear on exit

	cpuHist := make([]float64, 0, graphWidth)
	ramHist := make([]float64, 0, graphWidth)
	rxHist := make([]float64, 0, graphWidth)
	txHist := make([]float64, 0, graphWidth)

	// Seed CPU and traffic baselines.
	prevIdle, prevTotal := readCPUStat()
	prevRX, prevTX := interfaceTraffic()

	// Quit on q / Q / Ctrl-C.
	quit := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		for {
			n, _ := os.Stdin.Read(buf)
			if n > 0 && (buf[0] == 'q' || buf[0] == 'Q' || buf[0] == 3) {
				close(quit)
				return
			}
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	cfg, _ := ctx.Config.(*config.Config)

	// Clear screen and draw initial blank state.
	fmt.Print("\033[H\033[2J")
	drawDashboard(cpuHist, ramHist, rxHist, txHist, 0, 0, 0, 0, 0, 0, nil)

	for {
		select {
		case <-quit:
			return nil
		case <-ticker.C:
			// CPU delta.
			idle, total := readCPUStat()
			cpuPct := 0.0
			if dt := total - prevTotal; dt > 0 {
				cpuPct = float64(dt-(idle-prevIdle)) / float64(dt) * 100
			}
			prevIdle, prevTotal = idle, total

			// RAM.
			totalMB, usedMB := memoryUsage()
			ramPct := 0.0
			if totalMB > 0 {
				ramPct = float64(usedMB) * 100 / float64(totalMB)
			}

			// Traffic throughput (bytes/sec).
			rx, tx := interfaceTraffic()
			rxRate := float64(0)
			txRate := float64(0)
			if prevRX > 0 && rx >= prevRX {
				rxRate = float64(rx - prevRX)
			}
			if prevTX > 0 && tx >= prevTX {
				txRate = float64(tx - prevTX)
			}
			prevRX, prevTX = rx, tx

			cpuHist = appendCapped(cpuHist, cpuPct)
			ramHist = appendCapped(ramHist, ramPct)
			rxHist = appendCapped(rxHist, rxRate)
			txHist = appendCapped(txHist, txRate)

			tunnels := activeTunnels(cfg)

			drawDashboard(cpuHist, ramHist, rxHist, txHist,
				cpuPct, ramPct, rxRate, txRate,
				totalMB, usedMB, tunnels)
		}
	}
}

// tunnelInfo holds display info for an active tunnel.
type tunnelInfo struct {
	tag       string
	transport string
	backend   string
	domain    string
	status    string
}

// activeTunnels returns up to 10 tunnels with their status.
// DNSTT tunnels also generate a noizdns variant row (same service).
func activeTunnels(cfg *config.Config) []tunnelInfo {
	if cfg == nil || len(cfg.Tunnels) == 0 {
		return nil
	}

	var infos []tunnelInfo
	for _, t := range cfg.Tunnels {
		if t.IsDirectTransport() {
			continue
		}
		svcName := service.TunnelServiceName(t.Tag)
		status, err := service.Status(svcName)
		if err != nil {
			status = "unknown"
		}
		infos = append(infos, tunnelInfo{
			tag:       t.Tag,
			transport: t.Transport,
			backend:   t.Backend,
			domain:    t.Domain,
			status:    status,
		})
		// DNSTT serves both dnstt and noizdns clients on the same process.
		if t.Transport == config.TransportDNSTT {
			noizTag := strings.ReplaceAll(t.Tag, "dnstt", "noizdns")
			infos = append(infos, tunnelInfo{
				tag:       noizTag,
				transport: "noizdns",
				backend:   t.Backend,
				domain:    t.Domain,
				status:    status,
			})
		}
	}

	// Sort: active first, then by tag.
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].status == "active" && infos[j].status != "active" {
			return true
		}
		if infos[i].status != "active" && infos[j].status == "active" {
			return false
		}
		return infos[i].tag < infos[j].tag
	})

	if len(infos) > 10 {
		infos = infos[:10]
	}
	return infos
}

// appendCapped appends v to s and trims to graphWidth.
func appendCapped(s []float64, v float64) []float64 {
	s = append(s, v)
	if len(s) > graphWidth {
		s = s[len(s)-graphWidth:]
	}
	return s
}

// 256-color palette
const (
	cHeader   = "\033[38;5;75m"  // steel blue
	cDim      = "\033[38;5;242m" // gray
	cLabel    = "\033[38;5;255m" // bright white
	cCPU      = "\033[38;5;81m"  // sky blue
	cRAM      = "\033[38;5;177m" // lavender
	cRX       = "\033[38;5;114m" // soft green
	cTX       = "\033[38;5;222m" // warm yellow
	cOK       = "\033[38;5;78m"  // green
	cFail     = "\033[38;5;203m" // soft red
	cWarn     = "\033[38;5;214m" // orange
	cDivider  = "\033[38;5;238m" // dark gray
	cReset    = "\033[0m"
	cBold     = "\033[1m"
)

func drawDashboard(cpuH, ramH, rxH, txH []float64,
	cpuPct, ramPct, rxRate, txRate float64,
	totalMB, usedMB uint64, tunnels []tunnelInfo) {

	var b strings.Builder
	b.WriteString("\033[H") // cursor home

	// Header
	now := time.Now().Format("2006-01-02 15:04:05")
	b.WriteString("\r\n")
	b.WriteString(fmt.Sprintf("  %s%sSlipGate%s  %s%s%s    %s%s%s\r\n",
		cHeader, cBold, cReset, cDim, version.String(), cReset, cDim, now, cReset))
	b.WriteString(fmt.Sprintf("  %s────────────────────────────────────────────────────────────%s\r\n\r\n",
		cDivider, cReset))

	// Load average + uptime
	load := readLoadAvg()
	uptime := readUptime()
	b.WriteString(fmt.Sprintf("  %sload%s  %s    %suptime%s  %s\r\n\r\n",
		cDim, cReset, load, cDim, cReset, uptime))

	// CPU
	cpuColor := gaugeColor256(cpuPct)
	b.WriteString(fmt.Sprintf("  %s%sCPU%s  %s%5.1f%%%s  %s  %speak %5.1f%%  avg %5.1f%%%s\r\n",
		cBold, cLabel, cReset, cpuColor, cpuPct, cReset, sparkline(cpuH, 100, cCPU),
		cDim, histMax(cpuH), histAvg(cpuH), cReset))
	b.WriteString(fmt.Sprintf("       %s\r\n\r\n", progressBar(cpuPct, cCPU)))

	// RAM
	ramColor := gaugeColor256(ramPct)
	b.WriteString(fmt.Sprintf("  %s%sRAM%s  %s%5.1f%%%s  %s  %speak %5.1f%%  avg %5.1f%%%s\r\n",
		cBold, cLabel, cReset, ramColor, ramPct, cReset, sparkline(ramH, 100, cRAM),
		cDim, histMax(ramH), histAvg(ramH), cReset))
	b.WriteString(fmt.Sprintf("       %s  %s%d / %d MB%s\r\n\r\n",
		progressBar(ramPct, cRAM), cDim, usedMB, totalMB, cReset))

	// Traffic
	rxMax := autoMax(rxH)
	txMax := autoMax(txH)
	b.WriteString(fmt.Sprintf("  %s%s↓ RX%s %9s/s  %s  %speak %s/s%s\r\n",
		cBold, cRX, cReset, formatBytes(uint64(rxRate)), sparkline(rxH, rxMax, cRX),
		cDim, formatBytes(uint64(histMax(rxH))), cReset))
	b.WriteString(fmt.Sprintf("  %s%s↑ TX%s %9s/s  %s  %speak %s/s%s\r\n\r\n",
		cBold, cTX, cReset, formatBytes(uint64(txRate)), sparkline(txH, txMax, cTX),
		cDim, formatBytes(uint64(histMax(txH))), cReset))

	// Tunnels
	b.WriteString(fmt.Sprintf("  %s%sTunnels%s\r\n", cBold, cLabel, cReset))
	b.WriteString(fmt.Sprintf("  %s────────────────────────────────────────────────────────────%s\r\n",
		cDivider, cReset))
	if len(tunnels) == 0 {
		b.WriteString(fmt.Sprintf("  %s(none configured)%s\r\n", cDim, cReset))
	} else {
		b.WriteString(fmt.Sprintf("  %s%-16s %-12s %-7s %-22s %s%s\r\n",
			cDim, "TAG", "TYPE", "BACKEND", "DOMAIN", "STATUS", cReset))
		for _, t := range tunnels {
			dot := cFail + "●" + cReset
			statusText := cFail + t.status + cReset
			if t.status == "active" {
				dot = cOK + "●" + cReset
				statusText = cOK + t.status + cReset
			}
			domain := t.domain
			if len(domain) > 22 {
				domain = domain[:19] + "..."
			}
			b.WriteString(fmt.Sprintf("  %-16s %-12s %-7s %-22s %s %s\r\n",
				t.tag, t.transport, t.backend, domain, dot, statusText))
		}
	}

	// Services
	b.WriteString(fmt.Sprintf("\r\n  %s%sServices%s\r\n", cBold, cLabel, cReset))
	b.WriteString(fmt.Sprintf("  %s────────────────────────────────────────────────────────────%s\r\n",
		cDivider, cReset))
	for _, svc := range []struct{ name, label string }{
		{"slipgate-dnsrouter", "DNS Router"},
		{"slipgate-socks5", "SOCKS5 Proxy"},
	} {
		if service.Exists(svc.name) {
			status, _ := service.Status(svc.name)
			dot := cFail + "●" + cReset
			statusColor := cFail
			if status == "active" {
				dot = cOK + "●" + cReset
				statusColor = cOK
			}
			b.WriteString(fmt.Sprintf("  %-20s %s %s%s%s\r\n", svc.label, dot, statusColor, status, cReset))
		}
	}

	b.WriteString(fmt.Sprintf("\r\n  %sPress q or Ctrl+C to exit%s\r\n", cDim, cReset))
	b.WriteString("\033[J") // clear to end of screen

	fmt.Print(b.String())
}

// gaugeColor256 returns a 256-color ANSI code based on percentage thresholds.
func gaugeColor256(pct float64) string {
	switch {
	case pct >= 85:
		return cBold + cFail  // bold soft red
	case pct >= 60:
		return cBold + cWarn  // bold orange
	default:
		return cBold + cOK    // bold green
	}
}


// histMax returns the maximum value in a history slice.
func histMax(data []float64) float64 {
	m := 0.0
	for _, v := range data {
		if v > m {
			m = v
		}
	}
	return m
}

// histAvg returns the average value in a history slice.
func histAvg(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

// autoMax returns the max value in data, with a minimum floor of 1024 (1 KB/s)
// to avoid flat-lining the sparkline on idle traffic.
func autoMax(data []float64) float64 {
	m := 1024.0
	for _, v := range data {
		if v > m {
			m = v
		}
	}
	return m
}

func sparkline(data []float64, maxVal float64, color string) string {
	var b strings.Builder
	b.WriteString(color)
	pad := graphWidth - len(data)
	for i := 0; i < pad; i++ {
		b.WriteRune(sparkRunes[0])
	}
	for _, v := range data {
		idx := int(v / maxVal * float64(len(sparkRunes)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkRunes) {
			idx = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[idx])
	}
	b.WriteString("\033[0m")
	return b.String()
}

func progressBar(pct float64, color string) string {
	const width = 40
	filled := int(pct / 100 * width)
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	var b strings.Builder
	b.WriteString(color)
	for i := 0; i < filled; i++ {
		b.WriteRune('█')
	}
	b.WriteString("\033[2m")
	for i := filled; i < width; i++ {
		b.WriteRune('░')
	}
	b.WriteString("\033[0m")
	return b.String()
}

// readCPUStat reads the aggregate CPU line from /proc/stat and returns
// (idle, total) counters.
func readCPUStat() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, 0
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 {
		return 0, 0
	}
	var vals [10]uint64
	for i := 1; i < len(fields) && i <= 10; i++ {
		fmt.Sscanf(fields[i], "%d", &vals[i-1])
	}
	for _, v := range vals {
		total += v
	}
	idle = vals[3]
	return idle, total
}

// readLoadAvg reads the system load average.
func readLoadAvg() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "N/A"
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return strings.Join(fields[:3], "  ")
	}
	return "N/A"
}

// readUptime reads system uptime and formats it.
func readUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "N/A"
	}
	var secs float64
	fmt.Sscanf(string(data), "%f", &secs)
	d := int(secs) / 86400
	h := (int(secs) % 86400) / 3600
	m := (int(secs) % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh %dm", d, h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func interfaceTraffic() (uint64, uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 10 {
			continue
		}
		var rx, tx uint64
		fmt.Sscanf(fields[0], "%d", &rx)
		fmt.Sscanf(fields[8], "%d", &tx)
		return rx, tx
	}
	return 0, 0
}

func memoryUsage() (uint64, uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var total, available uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			fmt.Sscanf(line, "MemTotal: %d kB", &total)
		case strings.HasPrefix(line, "MemAvailable:"):
			fmt.Sscanf(line, "MemAvailable: %d kB", &available)
		}
	}
	totalMB := total / 1024
	usedMB := (total - available) / 1024
	return totalMB, usedMB
}

func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
