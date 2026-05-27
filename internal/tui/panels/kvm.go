package panels

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"hyperview/internal/store"

	"github.com/charmbracelet/lipgloss"
)

type exitRow struct {
	Reason uint32
	Count  uint64
}

var (
	cpuVendor     string
	vendorTracker sync.Once
)

func getCPUVendor() string {
	vendorTracker.Do(func() {
		cpuVendor = "intel" // default fallback
		data, err := os.ReadFile("/proc/cpuinfo")
		if err == nil {
			content := string(data)
			if strings.Contains(content, "AuthenticAMD") {
				cpuVendor = "amd"
			}
		}
	})
	return cpuVendor
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

		sb.WriteString(fmt.Sprintf("  %-15s [%s%s] %-6d (%5.1f%%)\n", mapExitReasonName(r.Reason), bar, empty, r.Count, pct))
	}

	return sb.String()
}

func mapExitReasonName(reason uint32) string {
	if getCPUVendor() == "amd" {
		// AMD SVM Architectural Exit Mappings (arch/x86/include/uapi/asm/svm.h)
		switch reason {
		case 78: // 0x4E
			return "INTR"
		case 94: // 0x5E
			return "EXCEPTION"
		case 112: // 0x70
			return "VMMCALL"
		case 114: // 0x72
			return "CPUID"
		case 122: // 0x7A
			return "HLT"
		case 123: // 0x7B
			return "IO_INSTR"
		case 124: // 0x7C
			return "MSR_ACCESS"
		case 127: // 0x7F
			return "SHUTDOWN"
		case 256: // 0x100
			return "NPF"
		default:
			return fmt.Sprintf("SVM_EXIT_%d", reason)
		}
	}

	// Intel VMX Architectural Exit Mappings (arch/x86/include/uapi/asm/vmx.h)
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
	case 23:
		return "VMREAD"
	case 24:
		return "VMWRITE"
	case 25:
		return "VMXOFF"
	case 30:
		return "IO_INSTR"
	case 31:
		return "RDMSR"
	case 32:
		return "WRMSR"
	case 48:
		return "EPT_VIOLATION"
	case 52:
		return "WBINVD"
	default:
		return fmt.Sprintf("VMX_EXIT_%d", reason)
	}
}
