package alert

import (
	"fmt"
	"os"
	"strings"

	"hyperview/internal/probe"
)

// FromProbeEvent converts an eBPF event into an alert. domainID and
// domainName are empty when the event does not concern a known VM; ok is
// false for events not worth reporting.
func FromProbeEvent(ev probe.Event, domainID, domainName string) (a Alert, ok bool) {
	a = Alert{Source: "ebpf", DomainID: domainID, DomainName: domainName, Last: ev.Time}
	switch ev.Type {
	case probe.EvKVMUserExit:
		a.Category = CatKVM
		if ev.A == probe.UserExitErrno {
			a.Rule, a.Subject = "kvm.run_error", fmt.Sprintf("tid %d", ev.TID)
			a.Severity = Warning
			if ev.B == 14 { // EFAULT: guest memory unbacked or a KVM bug
				a.Severity = Critical
			}
			a.Message = fmt.Sprintf("KVM_RUN failed: %s", errnoName(ev.B))
			a.Key = a.Rule + "|" + domainID + "|" + errnoName(ev.B)
			return a, true
		}
		name := probe.UserExitName(uint32(ev.A))
		a.Rule = "kvm.exit_" + strings.ToLower(name)
		a.Key = a.Rule + "|" + domainID
		switch name {
		case "INTERNAL_ERROR", "FAIL_ENTRY":
			a.Severity = Critical
			a.Message = fmt.Sprintf("KVM_EXIT_%s: the hypervisor cannot continue running this vCPU", name)
		case "SHUTDOWN":
			a.Severity = Warning
			a.Message = "KVM_EXIT_SHUTDOWN: guest triple fault (or reset through it)"
		case "SYSTEM_EVENT":
			a.Severity = Info
			a.Message = "KVM_EXIT_SYSTEM_EVENT: guest requested shutdown, reset or crash"
		case "MEMORY_FAULT":
			a.Severity = Warning
			a.Message = "KVM_EXIT_MEMORY_FAULT: guest access to memory KVM could not resolve"
		default:
			a.Severity = Warning
			a.Message = "KVM_EXIT_" + name
		}
		return a, true

	case probe.EvKVMEmulFail:
		a.Rule, a.Category, a.Severity = "kvm.emulation_failure", CatKVM, Warning
		a.Subject = fmt.Sprintf("tid %d", ev.TID)
		a.Key = a.Rule + "|" + domainID
		a.Message = fmt.Sprintf("instruction emulation failed at rip %#x", uint64(ev.A))
		return a, true

	case probe.EvKVMException:
		vec := probe.X86VectorName(uint32(ev.A))
		a.Rule, a.Category = "kvm.guest_exception", CatKVM
		a.Key = a.Rule + "|" + domainID + "|" + vec
		a.Severity = Warning
		a.Message = fmt.Sprintf("%s injected into guest (error code %#x)", vec, ev.B)
		if ev.A == 18 {
			a.Severity = Critical
			a.Message = "#MC machine check injected into guest"
		}
		return a, true

	case probe.EvOOMVictim:
		a.Rule, a.Category, a.Severity = "mem.oom_kill", CatMemory, Warning
		a.Key = fmt.Sprintf("mem.oom_kill|%d", ev.TGID)
		comm := ev.Comm
		if comm == "" {
			comm = procComm(ev.TGID)
		}
		a.Subject = fmt.Sprintf("%s[%d]", comm, ev.TGID)
		a.Message = fmt.Sprintf("OOM killer chose %s as victim", a.Subject)
		if domainID != "" {
			a.Severity = Critical
			a.Message = "OOM killer chose the hypervisor process of this VM"
		}
		return a, true

	case probe.EvSignal:
		if domainID == "" {
			return a, false
		}
		sig := probe.SignalName(ev.A)
		a.Rule, a.Category = "vm.signal", CatLifecycle
		a.Key = a.Rule + "|" + domainID + "|" + sig
		a.Subject = fmt.Sprintf("tid %d", ev.TID)
		switch ev.A {
		case 9, 15:
			a.Severity = Warning
			sender := "the kernel"
			if ev.B != 0 && uint32(ev.B) != ev.TGID {
				sender = fmt.Sprintf("%s[%d]", procComm(uint32(ev.B)), ev.B)
			}
			a.Message = fmt.Sprintf("%s sent by %s", sig, sender)
		default:
			a.Severity = Critical
			a.Message = fmt.Sprintf("hypervisor received %s (crash)", sig)
		}
		return a, true

	case probe.EvExit:
		if domainID == "" {
			return a, false
		}
		code, sig := (ev.A>>8)&0xff, ev.A&0x7f
		a.Rule, a.Category = "vm.process_exit", CatLifecycle
		a.Key = fmt.Sprintf("%s|%s|%d", a.Rule, domainID, ev.TGID)
		switch {
		case sig != 0:
			a.Severity = Critical
			a.Message = fmt.Sprintf("hypervisor %s[%d] killed by %s", ev.Comm, ev.TGID, probe.SignalName(sig))
			if ev.A&0x80 != 0 {
				a.Message += " (core dumped)"
			}
		case code != 0:
			a.Severity = Warning
			a.Message = fmt.Sprintf("hypervisor %s[%d] exited with status %d", ev.Comm, ev.TGID, code)
		default:
			a.Severity = Info
			a.Message = fmt.Sprintf("hypervisor %s[%d] exited", ev.Comm, ev.TGID)
		}
		return a, true

	case probe.EvBlockError:
		dev := probe.BlockDevName(uint32(ev.A))
		a.Rule, a.Category, a.Severity = "io.disk_errors", CatIO, Critical
		a.Subject = dev
		a.Key = a.Rule + "||" + dev
		a.DomainID, a.DomainName = "", ""
		a.Message = fmt.Sprintf("I/O error %s at sector %d (%d sectors)", errnoName(-ev.C), ev.B, ev.D)
		return a, true

	case probe.EvMCE:
		sevName := probe.MCESeverity(uint64(ev.A))
		a.Rule, a.Category = "hw.mce", CatHardware
		a.Subject = fmt.Sprintf("cpu%d bank%d", ev.CPU, ev.C)
		a.Key = a.Rule + "||" + a.Subject + "|" + sevName
		a.DomainID, a.DomainName = "", ""
		a.Severity = Critical
		if sevName == "corrected" {
			a.Severity = Warning
		}
		a.Message = fmt.Sprintf("%s machine check, status %#x addr %#x", sevName, uint64(ev.A), uint64(ev.B))
		return a, true
	}
	return a, false
}

var errnos = map[int64]string{1: "EPERM", 4: "EINTR", 5: "EIO", 11: "EAGAIN", 12: "ENOMEM",
	14: "EFAULT", 16: "EBUSY", 22: "EINVAL", 28: "ENOSPC", 61: "ENODATA", 62: "ETIME",
	67: "ENOLINK", 71: "EPROTO", 95: "EOPNOTSUPP", 110: "ETIMEDOUT", 121: "EREMOTEIO",
	125: "ECANCELED", 133: "EHWPOISON"}

func errnoName(e int64) string {
	if n, ok := errnos[e]; ok {
		return n
	}
	return fmt.Sprintf("errno %d", e)
}

func procComm(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}
