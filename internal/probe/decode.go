package probe

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// ExitArch selects how raw kvm_exit reasons are decoded.
type ExitArch int

const (
	ArchVMX ExitArch = iota // Intel VT-x
	ArchSVM                 // AMD-V (also Hygon)
	ArchARM64
	ArchUnknown
)

func (a ExitArch) String() string {
	return [...]string{"vmx", "svm", "arm64", "unknown"}[a]
}

var (
	hostArch     ExitArch
	hostArchOnce sync.Once
)

// HostExitArch detects the virtualization extension of the host CPU.
func HostExitArch() ExitArch {
	hostArchOnce.Do(func() {
		switch runtime.GOARCH {
		case "arm64":
			hostArch = ArchARM64
		case "amd64", "386":
			hostArch = ArchVMX
			if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
				s := string(b)
				if strings.Contains(s, "AuthenticAMD") || strings.Contains(s, "HygonGenuine") {
					hostArch = ArchSVM
				}
			}
		default:
			hostArch = ArchUnknown
		}
	})
	return hostArch
}

// ExitReasonKey normalizes a raw reason so equivalent exits share a name:
// VMX carries flag bits above the 16-bit basic reason.
func ExitReasonKey(arch ExitArch, raw uint32) uint32 {
	if arch == ArchVMX {
		return raw & 0xffff
	}
	return raw
}

// ExitReasonName decodes a raw kvm_exit reason.
func ExitReasonName(arch ExitArch, raw uint32) string {
	switch arch {
	case ArchVMX:
		if n, ok := vmxExits[raw&0xffff]; ok {
			return n
		}
		return fmt.Sprintf("VMX_%d", raw&0xffff)
	case ArchSVM:
		return svmExitName(raw)
	case ArchARM64:
		ret, ec := raw>>16, raw&0xffff
		switch ret {
		case 0:
			return "IRQ"
		case 1:
			return "SERROR"
		case 3:
			return "IL"
		case 2:
			if n, ok := arm64ESR[ec]; ok {
				return n
			}
			return fmt.Sprintf("EC_%#x", ec)
		}
		return fmt.Sprintf("ARM_EXC_%d", ret)
	}
	return fmt.Sprintf("EXIT_%d", raw)
}

var vmxExits = map[uint32]string{
	0: "EXCEPTION_NMI", 1: "EXTERNAL_INTERRUPT", 2: "TRIPLE_FAULT", 3: "INIT_SIGNAL",
	4: "SIPI_SIGNAL", 7: "INTERRUPT_WINDOW", 8: "NMI_WINDOW", 9: "TASK_SWITCH",
	10: "CPUID", 12: "HLT", 13: "INVD", 14: "INVLPG", 15: "RDPMC", 16: "RDTSC",
	18: "VMCALL", 19: "VMCLEAR", 20: "VMLAUNCH", 21: "VMPTRLD", 22: "VMPTRST",
	23: "VMREAD", 24: "VMRESUME", 25: "VMWRITE", 26: "VMOFF", 27: "VMON",
	28: "CR_ACCESS", 29: "DR_ACCESS", 30: "IO_INSTRUCTION", 31: "MSR_READ",
	32: "MSR_WRITE", 33: "INVALID_STATE", 34: "MSR_LOAD_FAIL", 36: "MWAIT",
	37: "MONITOR_TRAP_FLAG", 39: "MONITOR", 40: "PAUSE", 41: "MCE_DURING_VMENTRY",
	43: "TPR_BELOW_THRESHOLD", 44: "APIC_ACCESS", 45: "EOI_INDUCED", 46: "GDTR_IDTR",
	47: "LDTR_TR", 48: "EPT_VIOLATION", 49: "EPT_MISCONFIG", 50: "INVEPT",
	51: "RDTSCP", 52: "PREEMPTION_TIMER", 53: "INVVPID", 54: "WBINVD", 55: "XSETBV",
	56: "APIC_WRITE", 57: "RDRAND", 58: "INVPCID", 59: "VMFUNC", 60: "ENCLS",
	61: "RDSEED", 62: "PML_FULL", 63: "XSAVES", 64: "XRSTORS", 67: "UMWAIT",
	68: "TPAUSE", 74: "BUS_LOCK", 75: "NOTIFY",
}

var svmExits = map[uint32]string{
	0x060: "INTR", 0x061: "NMI", 0x062: "SMI", 0x063: "INIT", 0x064: "VINTR",
	0x065: "CR0_SEL_WRITE", 0x066: "IDTR_READ", 0x067: "GDTR_READ", 0x068: "LDTR_READ",
	0x069: "TR_READ", 0x06a: "IDTR_WRITE", 0x06b: "GDTR_WRITE", 0x06c: "LDTR_WRITE",
	0x06d: "TR_WRITE", 0x06e: "RDTSC", 0x06f: "RDPMC", 0x070: "PUSHF", 0x071: "POPF",
	0x072: "CPUID", 0x073: "RSM", 0x074: "IRET", 0x075: "SWINT", 0x076: "INVD",
	0x077: "PAUSE", 0x078: "HLT", 0x079: "INVLPG", 0x07a: "INVLPGA", 0x07b: "IOIO",
	0x07c: "MSR", 0x07d: "TASK_SWITCH", 0x07e: "FERR_FREEZE", 0x07f: "SHUTDOWN",
	0x080: "VMRUN", 0x081: "VMMCALL", 0x082: "VMLOAD", 0x083: "VMSAVE", 0x084: "STGI",
	0x085: "CLGI", 0x086: "SKINIT", 0x087: "RDTSCP", 0x088: "ICEBP", 0x089: "WBINVD",
	0x08a: "MONITOR", 0x08b: "MWAIT", 0x08c: "MWAIT_COND", 0x08d: "XSETBV",
	0x08e: "RDPRU", 0x08f: "EFER_WRITE_TRAP", 0x0a0: "INVLPGB", 0x0a1: "INVLPGB_ILLEGAL",
	0x0a2: "INVPCID", 0x0a3: "MCOMMIT", 0x0a5: "BUS_LOCK", 0x0a6: "IDLE_HLT",
	0x400: "NPF", 0x401: "AVIC_INCOMPLETE_IPI", 0x402: "AVIC_UNACCELERATED_ACCESS",
	0x403: "VMGEXIT", 0xffffffff: "ERR",
}

var x86Vectors = []string{"DE", "DB", "NMI", "BP", "OF", "BR", "UD", "NM", "DF", "CSO",
	"TS", "NP", "SS", "GP", "PF", "15", "MF", "AC", "MC", "XM", "VE", "CP"}

// X86VectorName returns the mnemonic of an x86 exception vector.
func X86VectorName(v uint32) string {
	if int(v) < len(x86Vectors) {
		return "#" + x86Vectors[v]
	}
	return fmt.Sprintf("#%d", v)
}

func svmExitName(code uint32) string {
	switch {
	case code <= 0x00f:
		return fmt.Sprintf("READ_CR%d", code)
	case code <= 0x01f:
		return fmt.Sprintf("WRITE_CR%d", code-0x10)
	case code <= 0x02f:
		return fmt.Sprintf("READ_DR%d", code-0x20)
	case code <= 0x03f:
		return fmt.Sprintf("WRITE_DR%d", code-0x30)
	case code <= 0x05f:
		return "EXCP_" + X86VectorName(code-0x40)
	case code >= 0x090 && code <= 0x09f:
		return fmt.Sprintf("CR%d_WRITE_TRAP", code-0x90)
	}
	if n, ok := svmExits[code]; ok {
		return n
	}
	return fmt.Sprintf("SVM_%#x", code)
}

var arm64ESR = map[uint32]string{
	0x00: "UNKNOWN", 0x01: "WFx", 0x03: "CP15_32", 0x04: "CP15_64", 0x05: "CP14_MR",
	0x06: "CP14_LS", 0x07: "FP_ASIMD", 0x0c: "CP14_64", 0x0e: "ILL", 0x11: "SVC32",
	0x15: "SVC64", 0x16: "HVC64", 0x17: "SMC64", 0x18: "SYS64", 0x19: "SVE",
	0x1c: "FPAC", 0x20: "IABT_LOW", 0x22: "PC_ALIGN", 0x24: "DABT_LOW", 0x26: "SP_ALIGN",
	0x28: "FP_EXC32", 0x2c: "FP_EXC64", 0x2f: "SERROR", 0x30: "BREAKPT_LOW",
	0x32: "SOFTSTP_LOW", 0x34: "WATCHPT_LOW", 0x38: "BKPT32", 0x3c: "BRK64",
}

var kvmUserExits = []string{"UNKNOWN", "EXCEPTION", "IO", "HYPERCALL", "DEBUG", "HLT",
	"MMIO", "IRQ_WINDOW_OPEN", "SHUTDOWN", "FAIL_ENTRY", "INTR", "SET_TPR", "TPR_ACCESS",
	"S390_SIEIC", "S390_RESET", "DCR", "NMI", "INTERNAL_ERROR", "OSI", "PAPR_HCALL",
	"S390_UCONTROL", "WATCHDOG", "S390_TSCH", "EPR", "SYSTEM_EVENT", "S390_STSI",
	"IOAPIC_EOI", "HYPERV", "ARM_NISV", "X86_RDMSR", "X86_WRMSR", "DIRTY_RING_FULL",
	"AP_RESET_HOLD", "X86_BUS_LOCK", "XEN", "RISCV_SBI", "RISCV_CSR", "NOTIFY",
	"LOONGARCH_IOCSR", "MEMORY_FAULT", "TDX"}

// UserExitErrno marks a userspace exit event caused by a KVM_RUN error.
const UserExitErrno = 0xffff

// UserExitName decodes a KVM_EXIT_* reason.
func UserExitName(r uint32) string {
	if int(r) < len(kvmUserExits) {
		return kvmUserExits[r]
	}
	return fmt.Sprintf("KVM_EXIT_%d", r)
}

var signals = map[int64]string{1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
	6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV",
	12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 31: "SIGSYS"}

func SignalName(sig int64) string {
	if n, ok := signals[sig]; ok {
		return n
	}
	return fmt.Sprintf("signal %d", sig)
}

// DropReasons maps skb_drop_reason values to names, read from kernel BTF
// because the enum changes between kernel versions.
type DropReasons map[uint32]string

func loadDropReasons() DropReasons {
	out := DropReasons{}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return out
	}
	var e *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &e); err != nil {
		return out
	}
	for _, v := range e.Values {
		out[uint32(v.Value)] = strings.TrimPrefix(v.Name, "SKB_DROP_REASON_")
	}
	return out
}

func (d DropReasons) Name(r uint32) string {
	if n, ok := d[r]; ok {
		return n
	}
	if r == 0 {
		return "UNSPECIFIED"
	}
	return fmt.Sprintf("REASON_%d", r)
}

// Benign reports whether a drop reason is normal packet consumption rather
// than an actual drop.
func (d DropReasons) Benign(r uint32) bool {
	switch d.Name(r) {
	case "SKB_CONSUMED", "SKB_NOT_DROPPED_YET", "NOT_DROPPED_YET", "CONSUMED":
		return true
	}
	return false
}

// MCE status bits (Intel SDM / AMD APM).
const (
	mciStatusUC  = 1 << 61
	mciStatusPCC = 1 << 57
)

// MCESeverity classifies an MCi_STATUS value as "corrected", "uncorrected"
// or "fatal" (processor context corrupt).
func MCESeverity(status uint64) string {
	switch {
	case status&mciStatusPCC != 0:
		return "fatal"
	case status&mciStatusUC != 0:
		return "uncorrected"
	}
	return "corrected"
}

var (
	blkNames   = map[uint32]string{}
	blkNamesMu sync.Mutex
)

// BlockDevName resolves a kernel-internal dev_t (12-bit major, 20-bit
// minor) as found in block tracepoints.
func BlockDevName(dev uint32) string {
	blkNamesMu.Lock()
	defer blkNamesMu.Unlock()
	if n, ok := blkNames[dev]; ok {
		return n
	}
	major, minor := dev>>20, dev&0xfffff
	name := fmt.Sprintf("%d:%d", major, minor)
	if b, err := os.ReadFile(fmt.Sprintf("/sys/dev/block/%d:%d/uevent", major, minor)); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "DEVNAME="); ok {
				name = v
			}
		}
	}
	blkNames[dev] = name
	return name
}
