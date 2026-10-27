package tui

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"hyperview/internal/alert"
	"hyperview/internal/config"
	"hyperview/internal/probe"
	"hyperview/internal/store"
)

func fixture() Sources {
	s := store.NewDomainStore()
	s.SetHost(store.HostStat{Hostname: "kvm-host-01", Kernel: "6.8.0-45-generic", Arch: "x86_64", CPUs: 32,
		Uptime: 50 * time.Hour, CPUPercent: 37.5, Load1: 7.2, MemTotalKiB: 128 << 20, MemAvailKiB: 40 << 20,
		SwapTotalKiB: 8 << 20, SwapFreeKiB: 7 << 20,
		PSI:   store.PSIStat{Available: true, CPUSome: 12.3, MemSome: 0.4, IOSome: 3.1, IOFull: 1.2},
		Disks: []store.HostDisk{{Name: "nvme0n1", IOPS: 1520, AvgUs: 180, P99Us: 2400}, {Name: "sda", IOPS: 40, P99Us: 81000, Errors: 2}}})
	for i, name := range []string{"web-frontend-01", "db-primary", "ci-runner-with-a-very-long-name-indeed", "fc-microvm"} {
		id := fmt.Sprintf("id-%d", i)
		s.Upsert(id, func(d *store.DomainSnapshot) {
			d.Name, d.Source, d.PID, d.State = name, "libvirt", 1000+i, "running"
			if i == 3 {
				d.Source = "firecracker"
			}
			if i == 2 {
				d.State, d.Reason = "paused", "ioerror"
			}
			d.UUID = "11111111-2222-4333-8444-55555555555" + fmt.Sprint(i)
			for v := 0; v < 4; v++ {
				d.VCPUs = append(d.VCPUs, store.VCPUStat{Index: v, TID: 2000 + v, CPUPercent: float64(10 * (v + i)), HostCPU: v,
					ExitRate: 12000, RunqAvgUs: 40, RunqP99Us: float64(800 * (i + 1) * (v + 1)), RunqMaxUs: 12000, HaltWaitRate: 300})
			}
			d.Mem = store.MemStat{MaxKiB: 8 << 20, BalloonKiB: 8 << 20, AvailableKiB: 8 << 20, UsableKiB: 3 << 20, UnusedKiB: 2 << 20, RssKiB: 6 << 20, MajorFltRate: 3}
			d.Ifaces = []store.IfaceStat{{Name: "vnet" + fmt.Sprint(i), RxBps: 1.2e6, TxBps: 340e3, RxPps: 900, TxPps: 400, DropRate: 2,
				KernelDropRate: 4, DropReasons: map[string]float64{"TAP_FILTER": 3, "QDISC_DROP": 1}}}
			d.Disks = []store.DiskStat{{Dev: "vda", RdBps: 5e6, WrBps: 1e6, RdIOPS: 300, WrIOPS: 80}}
			d.KVM = store.KVMStat{Available: true, ExitRate: 48000, ExitReasons: map[string]float64{"EPT_VIOLATION": 20000, "HLT": 15000, "MSR_WRITE": 9000, "IO_INSTRUCTION": 4000},
				UserExits: map[string]float64{"IO": 4000, "MMIO": 800}, IRQRate: 9000, HaltWaitRate: 1200, RunqP99Us: 3200}
			d.BlkLatAvgUs, d.BlkLatP99Us = 300, 4200
			if i == 0 {
				d.Migration = &store.MigrationStat{Status: "active", Operation: "migration-out", ElapsedMs: 42000, MemTotal: 8 << 30, MemRemaining: 3 << 30, MemProcessed: 5 << 30, Bps: 900e6, DirtyPageRate: 12000, ExpectedDownMs: 300}
			}
		})
		for t := 0; t < 60; t++ {
			s.Mutate(id, func(d *store.DomainSnapshot) { d.VCPUs[0].CPUPercent = float64((t * 7) % 100) })
			s.Commit(time.Now())
		}
	}
	eng := alert.NewEngine(config.Default().Alerts)
	eng.Raise(alert.Alert{Rule: "vm.signal", Severity: alert.Critical, Category: alert.CatLifecycle, DomainID: "id-1", DomainName: "db-primary", Subject: "tid 1001", Message: "hypervisor received SIGSEGV (crash)", Source: "ebpf"})
	eng.Raise(alert.Alert{Rule: "io.disk_errors", Severity: alert.Critical, Category: alert.CatIO, Subject: "sda", Message: "I/O error EIO at sector 123456 (8 sectors)", Source: "ebpf"})
	eng.Raise(alert.Alert{Rule: "kernel.soft_lockup", Severity: alert.Critical, Category: alert.CatKernel, Message: "watchdog: BUG: soft lockup - CPU#3 stuck for 23s! [kworker/3:1:123]", Source: "kmsg"})
	now := time.Now()
	th := config.Default().Thresholds
	samp := alert.Sample{Rule: "vcpu.runq_latency", Category: alert.CatSched, DomainID: "id-2", DomainName: "ci-runner", Subject: "vcpu3", Value: 9000, Level: th.RunqP99Us,
		Format: func(v float64) string { return fmt.Sprintf("p99 run-queue delay %.0fµs", v) }}
	eng.Evaluate(now, []alert.Sample{samp})
	eng.Evaluate(now.Add(5*time.Second), []alert.Sample{samp})
	return Sources{
		Store: s, Alerts: eng, Config: config.Default(),
		Probes: func() []probe.Status {
			return []probe.Status{{Feature: "kvm-exits", Probe: "kvm:kvm_exit", State: probe.Attached},
				{Feature: "mce", Probe: "mce:mce_record", State: probe.Unavailable, Err: "tracepoint not found"}}
		},
		EBPF:    func() (bool, string) { return true, "" },
		Kmsg:    func() string { return "" },
		Libvirt: func() string { return "/run/libvirt/libvirt-sock" },
	}
}

// TestRenderScreens renders every screen at several sizes and checks that
// nothing overflows the window. Set HV_RENDER=1 to print the screens.
func TestRenderScreens(t *testing.T) {
	src := fixture()
	type step struct {
		name string
		keys []string
	}
	steps := []step{
		{"dashboard", nil},
		{"filter", []string{"/", "d", "b", "enter"}},
		{"sort", []string{"esc", "s", "s"}},
		{"help", []string{"?"}},
		{"alerts", []string{"esc", "a", "j"}},
		{"status", []string{"p"}},
		{"log", []string{"L"}},
	}
	for i := 1; i <= 8; i++ {
		keys := []string{"esc", "g", "enter"}
		for j := 1; j < i; j++ {
			keys = append(keys, "right")
		}
		steps = append(steps, step{fmt.Sprintf("detail-tab%d", i), keys})
	}
	for _, size := range [][2]int{{160, 45}, {100, 30}, {95, 45}, {80, 45}, {60, 40}, {160, 22}, {80, 24}, {70, 20}, {20, 8}} {
		m := New(src, "")
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		for _, st := range steps {
			for _, k := range st.keys {
				m.key(k)
			}
			out := m.View().Content
			lines := strings.Split(out, "\n")
			if len(lines) > size[1] {
				t.Errorf("%s %v: %d lines", st.name, size, len(lines))
			}
			for n, l := range lines {
				if w := lipgloss.Width(l); w > size[0] {
					t.Errorf("%s %v: line %d is %d wide", st.name, size, n, w)
					break
				}
			}
			if r := os.Getenv("HV_RENDER"); r != "" && r == fmt.Sprintf("%dx%d", size[0], size[1]) {
				fmt.Printf("===== %s %dx%d\n%s\n", st.name, size[0], size[1], ansi.Strip(out))
			}
		}
	}
}
