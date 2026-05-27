package panels

import (
	"fmt"
	"strings"

	"hyperview/internal/store"

	"github.com/charmbracelet/lipgloss"
)

func RenderIOPanel(snap store.DomainSnapshot) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Underline(true).Foreground(lipgloss.Color("#5F5FDF"))

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Storage Block Device Disk I/O Matrix") + "\n\n")

	sb.WriteString(lipgloss.NewStyle().Bold(true).Render("Attached Devices:\n"))
	if len(snap.Disks) == 0 {
		sb.WriteString(" No virtual block storage disks detected.\n")
	} else {
		for _, disk := range snap.Disks {
			sb.WriteString(fmt.Sprintf(
				" ➔ %-10s | Read: %-12s (Reqs: %-6d) | Write: %-12s (Reqs: %-6d)\n",
				disk.Dev,
				FormatBytes(disk.RdBytes), disk.RdReqs,
				FormatBytes(disk.WrBytes), disk.WrReqs,
			))
		}
	}

	return sb.String()
}
