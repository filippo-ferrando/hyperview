package alert

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hyperview/internal/kmsg"
)

type kmsgRule struct {
	rule     string
	re       *regexp.Regexp
	sev      Severity
	cat      Category
	subject  int // capture group used as subject, 0 for none
	pidGroup int // capture group holding a pid used for VM attribution
}

// kmsgRules are tried in order; the first match wins.
var kmsgRules = []kmsgRule{
	// Kernel bugs and stalls.
	{rule: "kernel.oops", re: regexp.MustCompile(`^(?:Oops|general protection fault|kernel BUG at|BUG: unable to handle|Internal error: Oops)`), sev: Critical, cat: CatKernel},
	{rule: "kernel.panic", re: regexp.MustCompile(`^Kernel panic`), sev: Critical, cat: CatKernel},
	{rule: "kernel.soft_lockup", re: regexp.MustCompile(`BUG: soft lockup - CPU#(\d+)`), sev: Critical, cat: CatKernel, subject: 1},
	{rule: "kernel.hard_lockup", re: regexp.MustCompile(`(?i)hard LOCKUP on cpu (\d+)|Watchdog detected hard LOCKUP`), sev: Critical, cat: CatKernel, subject: 1},
	{rule: "kernel.rcu_stall", re: regexp.MustCompile(`rcu: INFO: \S+ (?:self-)?detected stalls?|rcu_\w+ (?:self-)?detected stall`), sev: Critical, cat: CatKernel},
	{rule: "kernel.hung_task", re: regexp.MustCompile(`^INFO: task (\S+):(\d+) blocked for more than`), sev: Warning, cat: CatKernel, subject: 1, pidGroup: 2},
	{rule: "kernel.bug", re: regexp.MustCompile(`^BUG: (\S.*)`), sev: Critical, cat: CatKernel},
	{rule: "kernel.warning", re: regexp.MustCompile(`^WARNING: CPU: \d+ PID: (\d+) at (\S+)`), sev: Warning, cat: CatKernel, subject: 2, pidGroup: 1},
	{rule: "kernel.hrtimer", re: regexp.MustCompile(`^hrtimer: interrupt took \d+ ns`), sev: Warning, cat: CatKernel},
	{rule: "kernel.clocksource", re: regexp.MustCompile(`(?i)clocksource.*unstable|TSC found unstable|Marking TSC unstable`), sev: Warning, cat: CatKernel},

	// Memory.
	{rule: "mem.oom_kill", re: regexp.MustCompile(`^Out of memory.*: Killed process (\d+) \(([^)]*)\)`), sev: Warning, cat: CatMemory, subject: 2, pidGroup: 1},
	{rule: "mem.oom_kill", re: regexp.MustCompile(`^Memory cgroup out of memory: Killed process (\d+) \(([^)]*)\)`), sev: Warning, cat: CatMemory, subject: 2, pidGroup: 1},
	{rule: "mem.alloc_failure", re: regexp.MustCompile(`^(\S+): page allocation failure`), sev: Warning, cat: CatMemory, subject: 1},
	{rule: "hw.memory_failure", re: regexp.MustCompile(`^Memory failure: (0x[0-9a-f]+)`), sev: Critical, cat: CatHardware, subject: 1},

	// Hardware.
	{rule: "hw.mce", re: regexp.MustCompile(`^mce: \[Hardware Error\]|^\[Hardware Error\]`), sev: Critical, cat: CatHardware},
	{rule: "hw.edac_ue", re: regexp.MustCompile(`EDAC \S+: .*\bUE\b|EDAC.*[Uu]ncorrect`), sev: Critical, cat: CatHardware},
	{rule: "hw.edac_ce", re: regexp.MustCompile(`EDAC \S+: .*\bCE\b|EDAC.*[Cc]orrected`), sev: Warning, cat: CatHardware},
	{rule: "hw.pcie_aer", re: regexp.MustCompile(`(?:AER|PCIe Bus Error).*severity=(?:Uncorrected|Fatal)`), sev: Critical, cat: CatHardware},
	{rule: "hw.pcie_aer", re: regexp.MustCompile(`(?:AER|PCIe Bus Error).*severity=Corrected`), sev: Info, cat: CatHardware},
	{rule: "hw.thermal", re: regexp.MustCompile(`(?i)temperature above threshold|cpu clock throttled|critical temperature reached`), sev: Warning, cat: CatHardware},

	// Storage.
	{rule: "io.disk_errors", re: regexp.MustCompile(`I/O error,? dev (\w+)`), sev: Critical, cat: CatIO, subject: 1},
	{rule: "io.disk_errors", re: regexp.MustCompile(`^Buffer I/O error on dev(?:ice)? (\w+)`), sev: Critical, cat: CatIO, subject: 1},
	{rule: "io.nvme", re: regexp.MustCompile(`^nvme (nvme\d+): .*(?:timeout|controller is down|Removing after probe failure|Device not ready|reset)`), sev: Critical, cat: CatIO, subject: 1},
	{rule: "io.scsi", re: regexp.MustCompile(`^sd \S+: \[(\w+)\] .*(?:FAILED Result|Sense Key : (?:Medium|Hardware) Error)`), sev: Critical, cat: CatIO, subject: 1},
	{rule: "io.ata", re: regexp.MustCompile(`^(ata\d+(?:\.\d+)?): (?:exception|failed command|hard resetting link|SError)`), sev: Warning, cat: CatIO, subject: 1},
	{rule: "io.fs_error", re: regexp.MustCompile(`^(?:EXT4-fs error|EXT4-fs \(\w+\): Remounting filesystem read-only|XFS \(\w+\): (?:Corruption|metadata I/O error|Filesystem has been shut down)|BTRFS (?:error|critical)|F2FS-fs.*error)`), sev: Critical, cat: CatIO},
	{rule: "io.md", re: regexp.MustCompile(`^md/raid\S*:(\w+): (?:Disk failure|Operation continuing on)`), sev: Critical, cat: CatIO, subject: 1},
	{rule: "io.blk_mq_hang", re: regexp.MustCompile(`blk_update_request: (?:critical|I/O) error`), sev: Critical, cat: CatIO},

	// Network.
	{rule: "net.tx_timeout", re: regexp.MustCompile(`NETDEV WATCHDOG: (\S+)`), sev: Critical, cat: CatNet, subject: 1},
	{rule: "net.link_down", re: regexp.MustCompile(`^(?:\S+ )?(\w[\w.-]*): (?:NIC )?Link is Down`), sev: Warning, cat: CatNet, subject: 1},

	// KVM. "kvm [pid]: ..." messages come from vcpu threads of a VM.
	{rule: "kvm.message", re: regexp.MustCompile(`^kvm \[(\d+)\]: (?:vcpu\d+, guest rIP: \S+ )?(.*)`), sev: Info, cat: CatKVM, pidGroup: 1},
	{rule: "kvm.message", re: regexp.MustCompile(`^kvm(?:_amd|_intel)?: (.*)`), sev: Info, cat: CatKVM},
	{rule: "kvm.vfio", re: regexp.MustCompile(`^vfio-pci (\S+): .*(?:error|failed|timeout)`), sev: Warning, cat: CatKVM, subject: 1},

	// User space crashes, worth reporting for hypervisor processes.
	{rule: "vm.segfault", re: regexp.MustCompile(`^(\S+)\[(\d+)\]: segfault at`), sev: Critical, cat: CatLifecycle, subject: 1, pidGroup: 2},
	{rule: "vm.trap", re: regexp.MustCompile(`^traps: (\S+)\[(\d+)\] (?:general protection|trap)`), sev: Critical, cat: CatLifecycle, subject: 1, pidGroup: 2},
}

// kvmNoise are kvm messages that are expected on healthy hosts.
var kvmNoise = regexp.MustCompile(`(?i)ignored (?:rd|wr)msr|unhandled rdmsr|unhandled wrmsr|kvm_set_msr_common|apic_access|SMT enabled|TSC scaling|disabled by bios`)

// PIDLookup resolves a host pid (process or thread) to the VM it belongs to.
type PIDLookup func(pid int) (domainID, domainName string, ok bool)

// FromKmsg classifies a kernel log record. Only kernel-facility records are
// considered; userspace writes to /dev/kmsg are ignored.
func FromKmsg(r kmsg.Record, lookup PIDLookup) (Alert, bool) {
	if r.Facility != 0 {
		return Alert{}, false
	}
	msg := strings.TrimSpace(r.Message)
	for i := range kmsgRules {
		kr := &kmsgRules[i]
		m := kr.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		a := Alert{Rule: kr.rule, Severity: kr.sev, Category: kr.cat, Source: "kmsg",
			Message: msg, Last: r.Time}
		if kr.subject > 0 && kr.subject < len(m) {
			a.Subject = m[kr.subject]
		}
		inVM := false
		if kr.pidGroup > 0 && lookup != nil {
			if pid, err := strconv.Atoi(m[kr.pidGroup]); err == nil {
				a.DomainID, a.DomainName, inVM = lookup(pid)
			}
		}
		switch kr.rule {
		case "kvm.message":
			// Informational kvm lines are capability banners at module load
			// or guest MSR probing; only warnings and worse are problems.
			if r.Priority > 4 || kvmNoise.MatchString(msg) {
				return Alert{}, false
			}
			a.Severity = Warning
		case "vm.segfault", "vm.trap":
			// Userspace crashes only matter here when a hypervisor crashed.
			if !inVM {
				return Alert{}, false
			}
		case "mem.oom_kill":
			if inVM {
				a.Severity = Critical
			}
			// Share the key with the eBPF OOM event so both merge.
			a.Key = "mem.oom_kill|" + m[kr.pidGroup]
		}
		if a.Key == "" {
			a.Key = a.Rule + "|" + a.DomainID + "|" + a.Subject
		}
		return a, true
	}
	// Unmatched records at crit or worse are still reported.
	if r.Priority <= 2 {
		return Alert{Rule: "kernel.critical", Severity: Warning, Category: CatKernel, Source: "kmsg",
			Message: msg, Last: r.Time, Key: "kernel.critical|" + firstWords(msg, 3)}, true
	}
	return Alert{}, false
}

func firstWords(s string, n int) string {
	f := strings.Fields(s)
	if len(f) > n {
		f = f[:n]
	}
	return strings.Join(f, " ")
}

// FollowKmsg classifies kernel log records until ctx is done. Records older
// than replay (relative to now) are skipped, so a restart reports recent
// problems without flooding the list with the whole boot log.
func FollowKmsg(ctx context.Context, r *kmsg.Reader, replay time.Duration, lookup PIDLookup, raise func(Alert)) error {
	go func() {
		<-ctx.Done()
		r.Close()
	}()
	since := time.Now().Add(-replay)
	for {
		rec, err := r.Next()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if rec.Time.Before(since) {
			continue
		}
		if a, ok := FromKmsg(rec, lookup); ok {
			raise(a)
		}
	}
}
