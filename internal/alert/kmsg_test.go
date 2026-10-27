package alert

import (
	"testing"
	"time"

	"hyperview/internal/kmsg"
)

func TestFromKmsg(t *testing.T) {
	lookup := func(pid int) (string, string, bool) {
		if pid == 4242 {
			return "vm-1", "web01", true
		}
		return "", "", false
	}
	cases := []struct {
		msg      string
		prio     int
		rule     string
		sev      Severity
		subject  string
		domain   string
		reported bool
	}{
		{msg: "watchdog: BUG: soft lockup - CPU#3 stuck for 23s! [qemu-system-x86:4242]", prio: 0, rule: "kernel.soft_lockup", sev: Critical, subject: "3", reported: true},
		{msg: "rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:", prio: 3, rule: "kernel.rcu_stall", sev: Critical, reported: true},
		{msg: "INFO: task qemu-system-x86:4242 blocked for more than 122 seconds.", prio: 3, rule: "kernel.hung_task", sev: Warning, subject: "qemu-system-x86", domain: "vm-1", reported: true},
		{msg: "Out of memory: Killed process 4242 (qemu-system-x86) total-vm:8000kB", prio: 3, rule: "mem.oom_kill", sev: Critical, subject: "qemu-system-x86", domain: "vm-1", reported: true},
		{msg: "Out of memory: Killed process 77 (chrome) total-vm:8000kB", prio: 3, rule: "mem.oom_kill", sev: Warning, subject: "chrome", reported: true},
		{msg: "I/O error, dev nvme0n1, sector 1234 op 0x1:(WRITE) flags 0x0 phys_seg 1 prio class 2", prio: 3, rule: "io.disk_errors", sev: Critical, subject: "nvme0n1", reported: true},
		{msg: "qemu-system-x86[4242]: segfault at 0 ip 000055 sp 00007f error 4 in qemu", prio: 6, rule: "vm.segfault", sev: Critical, subject: "qemu-system-x86", domain: "vm-1", reported: true},
		{msg: "firefox[99]: segfault at 0 ip 000055 sp 00007f error 4", prio: 6, reported: false},
		{msg: "kvm [4242]: vcpu0, guest rIP: 0xffffffff8100 ignored rdmsr: 0x4b564d05", prio: 6, reported: false},
		{msg: "kvm [4242]: vcpu0, guest rIP: 0xffffffff8100 disabled perfctr wrmsr", prio: 3, rule: "kvm.message", sev: Warning, domain: "vm-1", reported: true},
		{msg: "kvm_amd: Nested Paging enabled", prio: 6, reported: false},
		{msg: "kvm: vcpu 0: requested 1000 ns lapic timer period limited to 200000 ns", prio: 4, rule: "kvm.message", sev: Warning, reported: true},
		{msg: "mce: [Hardware Error]: Machine check events logged", prio: 2, rule: "hw.mce", sev: Critical, reported: true},
		{msg: "NETDEV WATCHDOG: eno1 (igb): transmit queue 0 timed out", prio: 4, rule: "net.tx_timeout", sev: Critical, subject: "eno1", reported: true},
		{msg: "random harmless line", prio: 6, reported: false},
		{msg: "something unknown but critical", prio: 2, rule: "kernel.critical", sev: Warning, reported: true},
	}
	for _, c := range cases {
		a, ok := FromKmsg(kmsg.Record{Priority: c.prio, Message: c.msg, Time: time.Now()}, lookup)
		if ok != c.reported {
			t.Errorf("%q: reported=%v want %v (%+v)", c.msg, ok, c.reported, a)
			continue
		}
		if !ok {
			continue
		}
		if a.Rule != c.rule || a.Severity != c.sev || a.Subject != c.subject || a.DomainID != c.domain {
			t.Errorf("%q: got rule=%s sev=%s subject=%q domain=%q", c.msg, a.Rule, a.Severity, a.Subject, a.DomainID)
		}
	}
}

func TestFromKmsgIgnoresUserFacility(t *testing.T) {
	if _, ok := FromKmsg(kmsg.Record{Facility: 1, Priority: 0, Message: "Kernel panic"}, nil); ok {
		t.Fatal("userspace record classified")
	}
}
