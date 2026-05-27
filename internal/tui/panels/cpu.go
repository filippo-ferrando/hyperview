package panels

import (
	"fmt"
	"strings"

	"hyperview/internal/store"

	"github.com/charmbracelet/lipgloss"
)

func RenderCPUPanel(snap store.DomainSnapshot, width int) string {
	if len(snap.VCPUs) == 0 {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Render("No vCPU distribution metrics reported.")
	}

	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("vCPU Usage Distribution Profile (%d Cores):\n\n", len(snap.VCPUs))))

	maxBarWidth := width - 18
	if maxBarWidth < 10 {
		maxBarWidth = 10
	}

	for _, vcpu := range snap.VCPUs {
		pct := vcpu.CPUPercent
		if pct > 100.0 {
			pct = 100.0
		}
		filledLength := int((pct / 100.0) * float64(maxBarWidth))
		if filledLength < 0 {
			filledLength = 0
		}

		bar := lipgloss.NewStyle().Foreground(lipgloss.Color("#3FDF7F")).Render(strings.Repeat("█", filledLength))
		empty := lipgloss.NewStyle().Foreground(lipgloss.Color("#303030")).Render(strings.Repeat("░", maxBarWidth-filledLength))

		sb.WriteString(fmt.Sprintf(" vCPU #%-2d [%s%s] %5.1f%%\n", vcpu.Index, bar, empty, vcpu.CPUPercent))
	}

	return sb.String()
}
