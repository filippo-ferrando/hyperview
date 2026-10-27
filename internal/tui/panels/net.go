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

	sb.WriteString(labelStyle.Render("Aggregate Download Sparkline (Rx): ") + sparklineStyle.Render(RenderSparkline(history.RX)) + "\n")
	sb.WriteString(labelStyle.Render("Aggregate Upload Sparkline (Tx):   ") + sparklineStyle.Render(RenderSparkline(history.TX)) + "\n\n")

	sb.WriteString(lipgloss.NewStyle().Bold(true).Render("Active Virtual Interfaces:\n"))
	if len(snap.Ifaces) == 0 {
		sb.WriteString(" No active network adapters detected.\n")
	} else {
		for _, iface := range snap.Ifaces {
			sb.WriteString(fmt.Sprintf(
				" ➔ %-10s | Rx: %-12s (%6.0f pps) | Tx: %-12s (%6.0f pps)\n",
				iface.Name,
				FormatBytes(iface.RxBps), iface.RxPps,
				FormatBytes(iface.TxBps), iface.TxPps,
			))
		}
	}

	return sb.String()
}

func RenderSparkline(history []float64) string {
	if len(history) == 0 {
		return "░░░░░░░░░░"
	}
	var max, min float64
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
		idx := int((v - min) / delta * float64(len(blocks)-1))
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

func FormatBytes(b float64) string {
	if b < 1024 {
		return fmt.Sprintf("%.0f B/s", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", b/1024.0)
	}
	return fmt.Sprintf("%.1f MB/s", b/(1024.0*1024.0))
}
