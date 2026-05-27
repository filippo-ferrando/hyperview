package panels

import (
	"fmt"

	"hyperview/internal/store"

	"github.com/charmbracelet/lipgloss"
)

func RenderMemPanel(snap store.DomainSnapshot) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Underline(true).Foreground(lipgloss.Color("#5F5FDF"))
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#D0D0D0"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)

	return lipgloss.JoinVertical(
		lipgloss.Left,
		titleStyle.Render("Memory Utilization Matrix & Kernel Fault Tracking"),
		"",
		fmt.Sprintf(" %s %s MiB", labelStyle.Render("Allocated Balloon Capacity:"), valStyle.Render(fmt.Sprintf("%d", snap.Mem.AllocKiB/1024))),
		fmt.Sprintf(" %s %s MiB", labelStyle.Render("Guest Reported Available:  "), valStyle.Render(fmt.Sprintf("%d", snap.Mem.AvailableKiB/1024))),
		fmt.Sprintf(" %s %s MiB", labelStyle.Render("Host Process Working RSS:  "), valStyle.Render(fmt.Sprintf("%d", snap.Mem.RssKiB/1024))),
		"",
		titleStyle.Render("Page Fault Counter Deltas"),
		"",
		fmt.Sprintf(" %s %s Context Switches/Ticks", labelStyle.Render("Minor Page Faults:"), valStyle.Render(fmt.Sprintf("%d", snap.Mem.MinorFaults))),
		fmt.Sprintf(" %s %s Disk Swaps/IO Requests", labelStyle.Render("Major Page Faults:"), valStyle.Render(fmt.Sprintf("%d", snap.Mem.MajorFaults))),
	)
}
