package collect

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"sort"
	"sync"
	"time"

	"hyperview/internal/probe"
	"hyperview/internal/store"
)

// histWindow is the minimum span latency percentiles are computed over.
const histWindow = time.Second

// KernelEvent is an eBPF event attributed to a domain when possible.
type KernelEvent struct {
	probe.Event
	DomainID   store.DomainID // empty when the event is not about a VM
	DomainName string
}

// EBPFCollector feeds eBPF counters into the store and forwards discrete
// kernel events. It degrades to a no-op when eBPF cannot be used.
type EBPFCollector struct {
	mu     sync.Mutex
	probes *probe.Probes
	err    error

	rates  *rateTracker
	runq   *probe.HistWindow
	blkDev *probe.HistWindow
	blkVM  *probe.HistWindow

	owners   map[uint32]store.DomainSnapshot // tgid -> domain, for event attribution
	lastSeen map[uint32]store.DomainSnapshot // targets of the previous tick
}

func NewEBPFCollector(cfg probe.Config) *EBPFCollector {
	ec := &EBPFCollector{
		rates:  newRateTracker(),
		runq:   probe.NewHistWindow(histWindow),
		blkDev: probe.NewHistWindow(histWindow),
		blkVM:  probe.NewHistWindow(histWindow),
		owners: make(map[uint32]store.DomainSnapshot),
	}
	ec.probes, ec.err = probe.Load(cfg)
	if ec.err != nil {
		slog.Warn("eBPF disabled, using libvirt and /proc only", slog.Any("reason", ec.err))
		return ec
	}
	attached := 0
	for _, st := range ec.probes.Status() {
		if st.State == probe.Attached {
			attached++
		}
	}
	slog.Info("eBPF probes attached", slog.Int("attached", attached), slog.Int("total", len(ec.probes.Status())))
	return ec
}

func (ec *EBPFCollector) Name() string { return "ebpf" }

// Enabled reports whether eBPF is active; reason explains why not.
func (ec *EBPFCollector) Enabled() (ok bool, reason string) {
	if ec.err != nil {
		return false, ec.err.Error()
	}
	return true, ""
}

// Status lists every probe with its state; nil when eBPF is disabled.
func (ec *EBPFCollector) Status() []probe.Status {
	if ec.probes == nil {
		return nil
	}
	return ec.probes.Status()
}

func (ec *EBPFCollector) Close() error {
	if ec.probes != nil {
		ec.probes.Close()
	}
	return nil
}

// RunEvents forwards kernel events to handle until ctx is done.
func (ec *EBPFCollector) RunEvents(ctx context.Context, handle func(KernelEvent)) {
	if ec.probes == nil {
		return
	}
	events := ec.probes.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			ke := KernelEvent{Event: ev}
			ec.mu.Lock()
			if d, ok := ec.owners[ev.TGID]; ok && ev.Type != probe.EvBlockError && ev.Type != probe.EvMCE {
				ke.DomainID, ke.DomainName = d.ID, d.Name
			}
			ec.mu.Unlock()
			handle(ke)
		}
	}
}

// ExitArch is the virtualization extension used to decode exit reasons.
func (ec *EBPFCollector) ExitArch() probe.ExitArch { return probe.HostExitArch() }

// DropReasonName decodes an skb drop reason of the running kernel.
func (ec *EBPFCollector) DropReasonName(r uint32) string {
	if ec.probes == nil {
		return fmt.Sprint(r)
	}
	return ec.probes.DropNames.Name(r)
}

func (ec *EBPFCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	if ec.probes == nil {
		return nil
	}
	ec.mu.Lock()
	defer ec.mu.Unlock()

	now := time.Now()
	snaps := s.Snapshot()

	targets := make(map[uint32]bool)
	ifaces := make(map[uint32]uint32)
	owners := make(map[uint32]store.DomainSnapshot)
	for _, d := range snaps {
		if d.PID <= 0 || (d.State != "running" && d.State != "paused") {
			continue
		}
		tgid := uint32(d.PID)
		targets[tgid] = true
		owners[tgid] = d
		for _, i := range d.Ifaces {
			if i.Ifindex > 0 {
				ifaces[uint32(i.Ifindex)] = tgid
			}
		}
	}
	// Also keep the previous tick's targets so exit events of VMs that
	// just stopped can still be attributed.
	ec.owners = maps.Clone(owners)
	for tgid, d := range ec.lastSeen {
		if _, ok := ec.owners[tgid]; !ok {
			ec.owners[tgid] = d
		}
	}
	ec.lastSeen = owners
	ec.probes.SetTargets(targets)
	ec.probes.SetIfaces(ifaces)

	arch := probe.HostExitArch()
	exits := ec.probes.ExitCounts()
	uexits := ec.probes.UserExitCounts()
	vmc := ec.probes.VMCounters()
	vcpus := ec.probes.VCPUCounters()
	runq := ec.probes.RunqHists()
	blkVM := ec.probes.BlockVMHists()
	drops := ec.probes.Drops()

	dropsByIf := make(map[uint32]map[string]float64)
	for k, n := range drops {
		if ec.probes.DropNames.Benign(k.Reason) {
			continue
		}
		name := ec.probes.DropNames.Name(k.Reason)
		r := ec.rates.rate(fmt.Sprintf("drop/%d/%d", k.Ifindex, k.Reason), float64(n), now)
		if dropsByIf[k.Ifindex] == nil {
			dropsByIf[k.Ifindex] = make(map[string]float64)
		}
		dropsByIf[k.Ifindex][name] += r
	}

	for tgid := range targets {
		d := owners[tgid]
		key := fmt.Sprintf("vm/%d/", tgid)

		reasons := make(map[string]float64)
		var total float64
		for raw, n := range exits[tgid] {
			r := ec.rates.rate(fmt.Sprintf("%sexit/%d", key, raw), float64(n), now)
			reasons[probe.ExitReasonName(arch, probe.ExitReasonKey(arch, raw))] += r
			total += r
		}
		users := make(map[string]float64)
		for raw, n := range uexits[tgid] {
			users[probe.UserExitName(raw)] += ec.rates.rate(fmt.Sprintf("%suexit/%d", key, raw), float64(n), now)
		}
		c := vmc[tgid]
		kvm := store.KVMStat{
			Available:     true,
			ExitRate:      total,
			ExitReasons:   reasons,
			UserExits:     users,
			IRQRate:       ec.rates.rate(key+"irq", float64(c.IrqInjections), now),
			ExceptionRate: ec.rates.rate(key+"exc", float64(c.Exceptions), now),
			EmulFailTotal: c.EmulFailures,
			HaltPollRate:  ec.rates.rate(key+"hpoll", float64(c.HaltPollsOk), now),
			HaltWaitRate:  ec.rates.rate(key+"hwait", float64(c.HaltWaits), now),
		}

		vcpuStats := make(map[int]store.VCPUStat)
		for _, v := range d.VCPUs {
			if v.TID <= 0 {
				continue
			}
			tid := uint32(v.TID)
			tkey := fmt.Sprintf("tid/%d/", tid)
			vc := vcpus[tid]
			v.ExitRate = ec.rates.rate(tkey+"exits", float64(vc.Exits), now)
			v.HaltWaitRate = ec.rates.rate(tkey+"hwait", float64(vc.HaltWaits), now)
			if h, ok := runq[tid]; ok {
				w := ec.runq.Window(tid, now, h)
				v.RunqAvgUs, v.RunqP99Us, v.RunqMaxUs = w.MeanUs(), w.Percentile(0.99), float64(w.MaxUs)
				kvm.RunqP99Us = max(kvm.RunqP99Us, v.RunqP99Us)
			}
			vcpuStats[v.Index] = v
		}

		var blkAvg, blkP99 float64
		if h, ok := blkVM[tgid]; ok {
			w := ec.blkVM.Window(tgid, now, h)
			blkAvg, blkP99 = w.MeanUs(), w.Percentile(0.99)
		}

		s.Mutate(d.ID, func(cur *store.DomainSnapshot) {
			cur.KVM = kvm
			cur.BlkLatAvgUs, cur.BlkLatP99Us = blkAvg, blkP99
			for i := range cur.VCPUs {
				if v, ok := vcpuStats[cur.VCPUs[i].Index]; ok && v.TID == cur.VCPUs[i].TID {
					cur.VCPUs[i].ExitRate = v.ExitRate
					cur.VCPUs[i].HaltWaitRate = v.HaltWaitRate
					cur.VCPUs[i].RunqAvgUs = v.RunqAvgUs
					cur.VCPUs[i].RunqP99Us = v.RunqP99Us
					cur.VCPUs[i].RunqMaxUs = v.RunqMaxUs
				}
			}
			for i := range cur.Ifaces {
				reasons := dropsByIf[uint32(cur.Ifaces[i].Ifindex)]
				var sum float64
				for _, r := range reasons {
					sum += r
				}
				cur.Ifaces[i].KernelDropRate = sum
				cur.Ifaces[i].DropReasons = reasons
			}
		})
	}

	ec.collectHostDisks(s, now)

	ec.rates.sweep()
	ec.runq.Sweep()
	ec.blkVM.Sweep()
	ec.blkDev.Sweep()
	return nil
}

func (ec *EBPFCollector) collectHostDisks(s *store.DomainStore, now time.Time) {
	hists := ec.probes.BlockDevHists()
	errs := ec.probes.BlockErrors()
	if len(hists) == 0 && len(errs) == 0 {
		return
	}
	var disks []store.HostDisk
	for dev, h := range hists {
		w := ec.blkDev.Window(dev, now, h)
		disks = append(disks, store.HostDisk{
			Name:   probe.BlockDevName(dev),
			IOPS:   ec.rates.rate(fmt.Sprintf("blk/%d", dev), float64(h.Count), now),
			AvgUs:  w.MeanUs(),
			P99Us:  w.Percentile(0.99),
			MaxUs:  float64(w.MaxUs),
			Errors: errs[dev],
		})
	}
	for dev, n := range errs {
		if _, ok := hists[dev]; !ok {
			disks = append(disks, store.HostDisk{Name: probe.BlockDevName(dev), Errors: n})
		}
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i].Name < disks[j].Name })
	s.MutateHost(func(h *store.HostStat) { h.Disks = disks })
}
