package collect

import (
	"context"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"hyperview/internal/store"
)

// HostCollector reads host CPU, memory, load and pressure stall information.
type HostCollector struct {
	mu       sync.Mutex
	fs       procfs.FS
	prevBusy float64
	prevAll  float64
	hostname string
	kernel   string
	arch     string
}

func NewHostCollector() (*HostCollector, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}
	hc := &HostCollector{fs: fs, arch: runtime.GOARCH}
	hc.hostname, _ = os.Hostname()
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		hc.kernel = unix.ByteSliceToString(u.Release[:])
		hc.arch = unix.ByteSliceToString(u.Machine[:])
	}
	return hc, nil
}

func (hc *HostCollector) Name() string { return "host" }
func (hc *HostCollector) Close() error { return nil }

func (hc *HostCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	var h store.HostStat
	h.Hostname, h.Kernel, h.Arch = hc.hostname, hc.kernel, hc.arch
	h.CPUs = runtime.NumCPU()

	if st, err := hc.fs.Stat(); err == nil {
		c := st.CPUTotal
		// Guest time is already included in user/nice.
		idle := c.Idle + c.Iowait
		all := c.User + c.Nice + c.System + c.IRQ + c.SoftIRQ + c.Steal + idle
		busy := all - idle
		if hc.prevAll > 0 && all > hc.prevAll {
			h.CPUPercent = 100 * (busy - hc.prevBusy) / (all - hc.prevAll)
		}
		hc.prevBusy, hc.prevAll = busy, all
		h.CPUs = max(len(st.CPU), 1)
	}
	if mi, err := hc.fs.Meminfo(); err == nil {
		h.MemTotalKiB = deref(mi.MemTotal)
		h.MemAvailKiB = deref(mi.MemAvailable)
		h.SwapTotalKiB = deref(mi.SwapTotal)
		h.SwapFreeKiB = deref(mi.SwapFree)
	}
	if la, err := hc.fs.LoadAvg(); err == nil {
		h.Load1 = la.Load1
	}
	var si unix.Sysinfo_t
	if unix.Sysinfo(&si) == nil {
		h.Uptime = time.Duration(si.Uptime) * time.Second
	}
	h.PSI = hc.psi()

	s.MutateHost(func(cur *store.HostStat) {
		h.Disks = cur.Disks // owned by the eBPF collector
		*cur = h
	})
	return nil
}

func (hc *HostCollector) psi() store.PSIStat {
	var p store.PSIStat
	read := func(res string) (some, full float64, ok bool) {
		st, err := hc.fs.PSIStatsForResource(res)
		if err != nil {
			return 0, 0, false
		}
		if st.Some != nil {
			some = st.Some.Avg10
		}
		if st.Full != nil {
			full = st.Full.Avg10
		}
		return some, full, true
	}
	var ok1, ok2, ok3 bool
	p.CPUSome, _, ok1 = read("cpu")
	p.MemSome, p.MemFull, ok2 = read("memory")
	p.IOSome, p.IOFull, ok3 = read("io")
	// PSI files exist but fail to read with EOPNOTSUPP when booted psi=0.
	p.Available = ok1 && ok2 && ok3
	return p
}

func deref(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}
