package panels

import (
	"fmt"
	"strings"

	"hyperview/internal/store"

	"github.com/charmbracelet/lipgloss"
)

func RenderMigrationPanel(snap store.DomainSnapshot, width int) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Underline(true).Foreground(lipgloss.Color("#5F5FDF"))
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#D0D0D0"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)

	if snap.Migration == nil || snap.Migration.Status != "active" {
		return lipgloss.JoinVertical(
			lipgloss.Left,
			titleStyle.Render("Live Virtual Machine Migration Engine Status"),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Render(" No live synchronization migration routines active for this node."),
		)
	}

	processed := snap.Migration.TotalPages - snap.Migration.DirtyPages
	pct := 0.0
	if snap.Migration.TotalPages > 0 {
		pct = (float64(processed) / float64(snap.Migration.TotalPages)) * 100.0
	}

	maxBarWidth := width - 16
	if maxBarWidth < 12 {
		maxBarWidth = 12
	}

	filledLength := int((pct / 100.0) * float64(maxBarWidth))
	bar := lipgloss.NewStyle().Foreground(lipgloss.Color("#00AFF0")).Render(strings.Repeat("█", filledLength))
	empty := lipgloss.NewStyle().Foreground(lipgloss.Color("#252525")).Render(strings.Repeat("░", maxBarWidth-filledLength))

	progressBarLayout := fmt.Sprintf(" [%s%s] %5.1f%%\n", bar, empty, pct)

	return lipgloss.JoinVertical(
		lipgloss.Left,
		titleStyle.Render("Live Virtual Machine Migration Engine Status"),
		"",
		fmt.Sprintf(" %s %s", labelStyle.Render("Cluster Sync Status:"), valStyle.Copy().Foreground(lipgloss.Color("#FFAF00")).Render(strings.ToUpper(snap.Migration.Status))),
		fmt.Sprintf(" %s %d ms", labelStyle.Render("Elapsed Duration:   "), snap.Migration.TotalTimeMs),
		"",
		labelStyle.Render(" Memory Mirroring Process Progression:"),
		progressBarLayout,
		fmt.Sprintf(" %s %s Pages / Total: %s Pages", labelStyle.Render("Synchronized Matrix:"), valStyle.Render(fmt.Sprintf("%d", processed)), valStyle.Render(fmt.Sprintf("%d", snap.Migration.TotalPages))),
		fmt.Sprintf(" %s %s Pages/s", labelStyle.Render("Kernel Dirty Page Rate:"), valStyle.Copy().Foreground(lipgloss.Color("#FF5F5F")).Render(fmt.Sprintf("%d", snap.Migration.DirtyPageRate))),
		fmt.Sprintf(" Network Bandwidth Speed:    %s Mbps", valStyle.Render(fmt.Sprintf("%.1f", snap.Migration.MbpsDown))),
		fmt.Sprintf(" Target Reswitch Threshold:   %s ms downtime window", valStyle.Copy().Foreground(lipgloss.Color("#5FFF5F")).Render(fmt.Sprintf("%d", snap.Migration.ExpectedDownMs))),
	)
}
