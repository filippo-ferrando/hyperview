package panels

import (
	"fmt"
	"strings"

	"hyperview/internal/store"

	"github.com/charmbracelet/lipgloss"
)

func RenderNetPanel(snap store.DomainSnapshot, history store.DomainHistory) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Underline(true).Foreground(lipgloss.Color("#5F5FDF"))
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#D0D0D0"))
	sparklineStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00AFFF")).Bold(true)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Network Interface Throughput Analytics") + "\n\n")

	sb.WriteString(labelStyle.Render("Aggregate Download Sparkline (Rx): ") + sparklineStyle.Render(RenderSparklineUint64(history.RX)) + "\n")
	sb.WriteString(labelStyle.Render("Aggregate Upload Sparkline (Tx):   ") + sparklineStyle.Render(RenderSparklineUint64(history.TX)) + "\n\n")

	sb.WriteString(lipgloss.NewStyle().Bold(true).Render("Active Virtual Interfaces:\n"))
	if len(snap.Ifaces) == 0 {
		sb.WriteString(" No active network adapters detected.\n")
	} else {
		for _, iface := range snap.Ifaces {
			sb.WriteString(fmt.Sprintf(
				" ➔ %-10s | Rx: %-12s (Pkts: %-6d) | Tx: %-12s (Pkts: %-6d)\n",
				iface.Name,
				FormatBytes(iface.RxBytes), iface.RxPkts,
				FormatBytes(iface.TxBytes), iface.TxPkts,
			))
		}
	}

	return sb.String()
}

func RenderSparklineUint64(history []uint64) string {
	if len(history) == 0 {
		return "░░░░░░░░░░"
	}
	var max, min uint64
	max, min = history[0], history[0]
	for _, v := range history {
		if v > max {
			max = v
		}
		if v < min {
			min = v
		}
	}
	blocks := []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	var sb strings.Builder
	delta := max - min
	for _, v := range history {
		if delta == 0 {
			sb.WriteRune('▄')
			continue
		}
		idx := int(float64(v-min) / float64(delta) * float64(len(blocks)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		sb.WriteRune(blocks[idx])
	}
	return sb.String()
}

func FormatBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B/s", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", float64(b)/1024.0)
	}
	return fmt.Sprintf("%.1f MB/s", float64(b)/(1024.0*1024.0))
}
