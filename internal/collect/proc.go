package collect

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"hyperview/internal/store"

	"github.com/prometheus/procfs"
)

// vcpuThreadRe matches the vCPU thread names used by QEMU ("CPU 3/KVM"),
// Firecracker ("fc_vcpu 3"), cloud-hypervisor ("vcpu3"), kvmtool
// ("kvm-vcpu-3") and crosvm ("crosvm_vcpu3").
var vcpuThreadRe = regexp.MustCompile(`^(?:CPU (\d+)/KVM|fc_vcpu (\d+)|vcpu(\d+)|kvm-vcpu-(\d+)|crosvm_vcpu(\d+))$`)

// threadRefresh bounds how often vCPU thread IDs are rediscovered.
const threadRefresh = 10 * time.Second

func vcpuIndex(comm string) (int, bool) {
	m := vcpuThreadRe.FindStringSubmatch(comm)
	if m == nil {
		return 0, false
	}
	for _, g := range m[1:] {
		if g != "" {
			n, err := strconv.Atoi(g)
			return n, err == nil
		}
	}
	return 0, false
}

type vcpuThreads struct {
	tids    map[int]int // vcpu index -> tid
	fetched time.Time
}

// ProcCollector reads host-side process data for every domain with a known
// hypervisor PID: RSS, page fault rates and vCPU thread IDs. For domains
// without libvirt it also derives per-vCPU CPU usage from thread times.
type ProcCollector struct {
	mu      sync.Mutex
	fs      procfs.FS
	rates   *rateTracker
	threads map[int]*vcpuThreads
}

func NewProcCollector() (*ProcCollector, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}
	return &ProcCollector{
		fs:      fs,
		rates:   newRateTracker(),
		threads: make(map[int]*vcpuThreads),
	}, nil
}

func (pc *ProcCollector) Name() string { return "proc" }
func (pc *ProcCollector) Close() error { return nil }

func (pc *ProcCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	now := time.Now()
	livePIDs := make(map[int]bool)
	for _, snap := range s.Snapshot() {
		if snap.PID <= 0 {
			continue
		}
		livePIDs[snap.PID] = true
		proc, err := pc.fs.Proc(snap.PID)
		if err != nil {
			continue
		}
		stat, err := proc.Stat()
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%d", snap.PID)
		rss := uint64(stat.ResidentMemory() / 1024)
		minor := pc.rates.rate(key+"/minflt", float64(stat.MinFlt), now)
		major := pc.rates.rate(key+"/majflt", float64(stat.MajFlt), now)

		vt := pc.vcpuThreads(snap.PID, now)
		ownCPU := snap.Source != "libvirt"
		var vcpus []store.VCPUStat
		if ownCPU {
			vcpus = pc.threadCPU(snap.PID, vt, now)
		}

		s.Mutate(snap.ID, func(d *store.DomainSnapshot) {
			d.Mem.RssKiB = rss
			d.Mem.MinorFltRate = minor
			d.Mem.MajorFltRate = major
			if ownCPU {
				// Keep eBPF-filled fields of existing vCPUs.
				for i := range vcpus {
					if i < len(d.VCPUs) && d.VCPUs[i].TID == vcpus[i].TID {
						old := d.VCPUs[i]
						old.CPUPercent, old.HostCPU = vcpus[i].CPUPercent, vcpus[i].HostCPU
						vcpus[i] = old
					}
				}
				d.VCPUs = vcpus
			}
			for i := range d.VCPUs {
				d.VCPUs[i].TID = vt.tids[d.VCPUs[i].Index]
			}
		})
	}

	for pid := range pc.threads {
		if !livePIDs[pid] {
			delete(pc.threads, pid)
		}
	}
	pc.rates.sweep()
	return nil
}

func (pc *ProcCollector) vcpuThreads(pid int, now time.Time) *vcpuThreads {
	vt := pc.threads[pid]
	if vt != nil && now.Sub(vt.fetched) < threadRefresh {
		return vt
	}
	vt = &vcpuThreads{tids: make(map[int]int), fetched: now}
	pc.threads[pid] = vt
	threads, err := pc.fs.AllThreads(pid)
	if err != nil {
		return vt
	}
	for _, t := range threads {
		comm, err := t.Comm()
		if err != nil {
			continue
		}
		if idx, ok := vcpuIndex(comm); ok {
			vt.tids[idx] = t.PID
		}
	}
	return vt
}

func (pc *ProcCollector) threadCPU(pid int, vt *vcpuThreads, now time.Time) []store.VCPUStat {
	n := 0
	for idx := range vt.tids {
		n = max(n, idx+1)
	}
	out := make([]store.VCPUStat, 0, n)
	for idx := 0; idx < n; idx++ {
		tid, ok := vt.tids[idx]
		if !ok {
			continue
		}
		v := store.VCPUStat{Index: idx, TID: tid, HostCPU: -1}
		if t, err := pc.fs.Thread(pid, tid); err == nil {
			if st, err := t.Stat(); err == nil {
				v.CPUPercent = pc.rates.rate(fmt.Sprintf("%d/%d/cpu", pid, tid), st.CPUTime(), now) * 100
				v.HostCPU = int(st.Processor)
			}
		}
		out = append(out, v)
	}
	return out
}
