package alert

import (
	"fmt"
	"time"

	"hyperview/internal/config"
	"hyperview/internal/store"
)

// Detector derives condition samples and counter-based events from store
// snapshots. Call Run once per committed tick.
type Detector struct {
	eng *Engine
	th  config.Thresholds

	prev   map[string]store.DomainSnapshot
	primed bool
}

func NewDetector(eng *Engine, th config.Thresholds) *Detector {
	return &Detector{eng: eng, th: th, prev: make(map[string]store.DomainSnapshot)}
}

func (d *Detector) Run(now time.Time, host store.HostStat, doms []store.DomainSnapshot) {
	var ss []Sample
	ss = d.hostSamples(ss, &host)
	for i := range doms {
		ss = d.domainSamples(ss, &doms[i])
	}
	d.eng.Evaluate(now, ss)

	cur := make(map[string]store.DomainSnapshot, len(doms))
	for _, dom := range doms {
		cur[dom.ID] = dom
		if p, ok := d.prev[dom.ID]; ok {
			d.domainEvents(&p, &dom)
		} else if d.primed {
			d.eng.Raise(Alert{Rule: "vm.appeared", Severity: Info, Category: CatLifecycle, Source: "metrics",
				DomainID: dom.ID, DomainName: dom.Name, Message: fmt.Sprintf("%s VM detected (%s)", dom.Source, dom.State)})
		}
	}
	for id, p := range d.prev {
		if _, ok := cur[id]; !ok {
			d.eng.Raise(Alert{Rule: "vm.disappeared", Severity: Info, Category: CatLifecycle, Source: "metrics",
				DomainID: id, DomainName: p.Name, Message: "VM no longer present"})
		}
	}
	d.prev = cur
	d.primed = true
}

func (d *Detector) hostSamples(ss []Sample, h *store.HostStat) []Sample {
	if h.MemTotalKiB > 0 {
		free := 100 * float64(h.MemAvailKiB) / float64(h.MemTotalKiB)
		ss = append(ss, Sample{Rule: "host.mem_low", Category: CatMemory, Subject: "host",
			Value: free, Level: d.th.HostMemFreePct, LowerWorse: true,
			Format: func(v float64) string { return fmt.Sprintf("host memory available %.1f%%", v) }})
	}
	if h.PSI.Available {
		psi := func(rule, what string, v float64, l config.Level) Sample {
			return Sample{Rule: rule, Category: CatSched, Subject: "host", Value: v, Level: l,
				Format: func(v float64) string { return fmt.Sprintf("%s pressure %.1f%% (avg10)", what, v) }}
		}
		mem := psi("host.psi_mem_some", "memory some", h.PSI.MemSome, d.th.PSIMemSome)
		mem.Category = CatMemory
		memFull := psi("host.psi_mem_full", "memory full", h.PSI.MemFull, d.th.PSIMemFull)
		memFull.Category = CatMemory
		io := psi("host.psi_io_full", "I/O full", h.PSI.IOFull, d.th.PSIIOFull)
		io.Category = CatIO
		ss = append(ss, psi("host.psi_cpu_some", "CPU some", h.PSI.CPUSome, d.th.PSICPUSome), mem, memFull, io)
	}
	for _, disk := range h.Disks {
		if disk.IOPS == 0 && disk.P99Us == 0 {
			continue
		}
		ss = append(ss, Sample{Rule: "io.disk_latency", Category: CatIO, Subject: disk.Name,
			Value: disk.P99Us, Level: d.th.DiskP99Us,
			Format: func(v float64) string { return fmt.Sprintf("p99 request latency %s", fmtUs(v)) }})
	}
	return ss
}

func (d *Detector) domainSamples(ss []Sample, dom *store.DomainSnapshot) []Sample {
	base := Sample{DomainID: dom.ID, DomainName: dom.Name}
	with := func(s Sample) Sample {
		s.DomainID, s.DomainName = base.DomainID, base.DomainName
		return s
	}

	switch {
	case dom.State == "crashed":
		ss = append(ss, with(Sample{Rule: "vm.crashed", Category: CatLifecycle, Value: 1,
			Level:  config.Level{Crit: 1},
			Format: func(float64) string { return "guest crashed" + reasonSuffix(dom.Reason) }}))
	case dom.State == "paused" && isErrorPause(dom.Reason):
		ss = append(ss, with(Sample{Rule: "vm.paused_error", Category: CatLifecycle, Value: 1,
			Level:  config.Level{Crit: 1},
			Format: func(float64) string { return "guest paused: " + dom.Reason }}))
	}
	if !dom.Running() {
		return ss
	}

	for _, v := range dom.VCPUs {
		sub := fmt.Sprintf("vcpu%d", v.Index)
		if dom.KVM.Available {
			ss = append(ss, with(Sample{Rule: "vcpu.runq_latency", Category: CatSched, Subject: sub,
				Value: v.RunqP99Us, Level: d.th.RunqP99Us,
				Format: func(v float64) string { return fmt.Sprintf("p99 run-queue delay %s (host CPU contention)", fmtUs(v)) }}))
			ss = append(ss, with(Sample{Rule: "kvm.exit_storm", Category: CatKVM, Subject: sub,
				Value: v.ExitRate, Level: d.th.VCPUExitRate,
				Format: func(v float64) string { return fmt.Sprintf("%.0f VM exits/s%s", v, topExit(dom.KVM.ExitReasons)) }}))
		}
	}

	m := dom.Mem
	if m.AvailableKiB > 0 && m.UsableKiB > 0 {
		ss = append(ss, with(Sample{Rule: "mem.guest_low", Category: CatMemory,
			Value: 100 * float64(m.UsableKiB) / float64(m.AvailableKiB), Level: d.th.GuestMemFreePct, LowerWorse: true,
			Format: func(v float64) string { return fmt.Sprintf("guest usable memory %.1f%%", v) }}))
	}
	ss = append(ss, with(Sample{Rule: "mem.guest_swap_in", Category: CatMemory,
		Value: m.SwapInRate, Level: d.th.GuestSwapInKiBs,
		Format: func(v float64) string { return fmt.Sprintf("guest swapping in %.0f KiB/s", v) }}))
	ss = append(ss, with(Sample{Rule: "mem.host_major_faults", Category: CatMemory,
		Value: m.MajorFltRate, Level: d.th.MajorFaultRate,
		Format: func(v float64) string {
			return fmt.Sprintf("hypervisor process %.0f major faults/s (guest RAM swapped on host)", v)
		}}))

	if dom.KVM.Available && (dom.BlkLatP99Us > 0 || dom.BlkLatAvgUs > 0) {
		ss = append(ss, with(Sample{Rule: "io.vm_latency", Category: CatIO,
			Value: dom.BlkLatP99Us, Level: d.th.VMBlockP99Us,
			Format: func(v float64) string { return fmt.Sprintf("p99 block latency %s", fmtUs(v)) }}))
	}

	for _, i := range dom.Ifaces {
		drops := max(i.DropRate, i.KernelDropRate)
		ss = append(ss, with(Sample{Rule: "net.drops", Category: CatNet, Subject: i.Name,
			Value: drops, Level: d.th.NetDropRate,
			Format: func(v float64) string { return fmt.Sprintf("%.0f packets dropped/s%s", v, topExit(i.DropReasons)) }}))
	}
	return ss
}

// domainEvents raises events for counters that increased since the last tick.
func (d *Detector) domainEvents(p, c *store.DomainSnapshot) {
	ev := func(rule string, sev Severity, cat Category, subject, msg string) {
		d.eng.Raise(Alert{Rule: rule, Severity: sev, Category: cat, Source: "metrics",
			DomainID: c.ID, DomainName: c.Name, Subject: subject, Message: msg})
	}
	if p.State != c.State {
		sev := Info
		if c.State == "crashed" || c.State == "shut off" && (c.Reason == "crashed" || c.Reason == "failed") {
			sev = Critical
		}
		ev("vm.state", sev, CatLifecycle, "", fmt.Sprintf("%s → %s%s", p.State, c.State, reasonSuffix(c.Reason)))
	}
	if c.Mem.HugetlbFail > p.Mem.HugetlbFail {
		ev("mem.hugetlb_fail", Warning, CatMemory, "",
			fmt.Sprintf("%d guest hugetlb allocation failures", c.Mem.HugetlbFail-p.Mem.HugetlbFail))
	}
	prevIf := make(map[string]store.IfaceStat, len(p.Ifaces))
	for _, i := range p.Ifaces {
		prevIf[i.Name] = i
	}
	for _, i := range c.Ifaces {
		o, ok := prevIf[i.Name]
		if !ok {
			continue
		}
		if n := (i.RxErrs + i.TxErrs) - (o.RxErrs + o.TxErrs); i.RxErrs+i.TxErrs > o.RxErrs+o.TxErrs {
			ev("net.errors", Warning, CatNet, i.Name, fmt.Sprintf("%d interface errors", n))
		}
	}
	prevDisk := make(map[string]int64, len(p.Disks))
	for _, dk := range p.Disks {
		prevDisk[dk.Dev] = dk.ErrsTotal
	}
	for _, dk := range c.Disks {
		if o, ok := prevDisk[dk.Dev]; ok && o >= 0 && dk.ErrsTotal > o {
			ev("io.vm_disk_errors", Critical, CatIO, dk.Dev, fmt.Sprintf("%d failed I/O requests", dk.ErrsTotal-o))
		}
	}
	if m := c.Migration; m != nil && (p.Migration == nil || p.Migration.Status != m.Status) {
		sev := Info
		if m.Status == "failed" {
			sev = Warning
		}
		ev("vm.migration", sev, CatLifecycle, "", fmt.Sprintf("%s %s", m.Operation, m.Status))
	}
}

func isErrorPause(reason string) bool {
	switch reason {
	case "ioerror", "watchdog", "crashed", "postcopy failed", "api error",
		"io-error", "guest-panicked", "internal-error": // last three from QMP
		return true
	}
	return false
}

func reasonSuffix(r string) string {
	if r == "" {
		return ""
	}
	return " (" + r + ")"
}

// topExit names the largest contributor of a rate breakdown.
func topExit(m map[string]float64) string {
	var name string
	var best float64
	for k, v := range m {
		if v > best || v == best && k < name {
			name, best = k, v
		}
	}
	if name == "" {
		return ""
	}
	return ", mostly " + name
}

func fmtUs(us float64) string {
	switch {
	case us >= 1e6:
		return fmt.Sprintf("%.2fs", us/1e6)
	case us >= 1e3:
		return fmt.Sprintf("%.1fms", us/1e3)
	}
	return fmt.Sprintf("%.0fµs", us)
}
