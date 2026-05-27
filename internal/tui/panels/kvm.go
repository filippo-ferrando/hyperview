package panels

import (
	"fmt"
	"sort"
	"strings"

	"hyperview/internal/store"

	"github.com/charmbracelet/lipgloss"
)

type exitRow struct {
	Reason uint32
	Count  uint64
}

func RenderKVMPanel(snap store.DomainSnapshot, width int) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Underline(true).Foreground(lipgloss.Color("#5F5FDF"))

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("KVM Core Kernel Event Exits & IRQ Inject Histogram") + "\n\n")

	if !snap.KVMEvents.Available || len(snap.KVMEvents.ExitReasons) == 0 {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Render(" eBPF hardware virtualization metrics currently dormant.\n"))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf(" Aggregate Hardware Interrupts (IRQ Injections): %d\n\n", snap.KVMEvents.IRQInjections))
	sb.WriteString(lipgloss.NewStyle().Bold(true).Render(" Top Virtual Machine Execution Exits:") + "\n")

	var rows []exitRow
	var totalExits uint64
	for r, c := range snap.KVMEvents.ExitReasons {
		rows = append(rows, exitRow{Reason: r, Count: c})
		totalExits += c
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Count > rows[j].Count })

	// Bar size tracker optimized for zero layout line wrapping
	maxBarWidth := width - 45
	if maxBarWidth < 10 {
		maxBarWidth = 10
	}

	limit := len(rows)
	if limit > 10 {
		limit = 10
	}

	for i := 0; i < limit; i++ {
		r := rows[i]
		pct := 0.0
		if totalExits > 0 {
			pct = (float64(r.Count) / float64(totalExits)) * 100.0
		}

		filledLength := int((pct / 100.0) * float64(maxBarWidth))
		if filledLength < 0 {
			filledLength = 0
		}
		if filledLength > maxBarWidth {
			filledLength = maxBarWidth
		}

		bar := lipgloss.NewStyle().Foreground(lipgloss.Color("#D15FDF")).Render(strings.Repeat("█", filledLength))
		empty := lipgloss.NewStyle().Foreground(lipgloss.Color("#252525")).Render(strings.Repeat("░", maxBarWidth-filledLength))

		sb.WriteString(fmt.Sprintf("  %-12s [%s%s] %-6d (%5.1f%%)\n", mapExitReasonName(r.Reason), bar, empty, r.Count, pct))
	}

	return sb.String()
}

func mapExitReasonName(reason uint32) string {
	switch reason {
	case 0:
		return "EXCEPTION"
	case 1:
		return "EXTERNAL_INT"
	case 2:
		return "TRIPLE_FAULT"
	case 10:
		return "CPUID"
	case 12:
		return "HLT"
	case 30:
		return "IO_INSTR"
	case 31:
		return "MSR_ACCESS"
	case 48:
		return "EPT_VIOLATION"
	default:
		return fmt.Sprintf("EXIT_%d", reason)
	}
}
