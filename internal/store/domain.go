package store

import (
	"sort"
	"sync"
	"time"
)

// HistoryLen is the number of samples kept per time series.
const HistoryLen = 120

type DomainID = string

// DomainSnapshot is a point-in-time view of all metrics for one VM.
// Rates are always per second; counters suffixed with Total are cumulative.
type DomainSnapshot struct {
	ID     DomainID
	Name   string
	UUID   string
	Source string // libvirt | qemu | firecracker | cloud-hypervisor | kvm
	PID    int
	State  string
	Reason string // libvirt state reason (e.g. "ioerror"), empty when unknown

	VCPUs     []VCPUStat
	Mem       MemStat
	Ifaces    []IfaceStat
	Disks     []DiskStat
	KVM       KVMStat
	Migration *MigrationStat

	CollectedAt time.Time
}

type VCPUStat struct {
	Index      int
	TID        int
	CPUPercent float64
	HostCPU    int

	// eBPF
	ExitRate     float64 // kvm exits/s
	ExitAvgNs    float64 // mean time from kvm_exit to the next kvm_entry
	RunqAvgUs    float64 // mean scheduler run-queue delay over the last interval
	RunqP99Us    float64 // p99 run-queue delay over the last interval
	RunqMaxUs    float64
	HaltWaitRate float64 // halts that ended in a real sleep, per second
}

type MemStat struct {
	MaxKiB       uint64 // configured maximum
	BalloonKiB   uint64 // current balloon size (actual)
	AvailableKiB uint64 // total memory seen by the guest
	UsableKiB    uint64 // memory the guest could use without swapping
	UnusedKiB    uint64 // memory left completely unused by the guest
	RssKiB       uint64 // host RSS of the hypervisor process
	SwapInRate   float64
	SwapOutRate  float64
	MinorFltRate float64 // host-side minor faults/s of the hypervisor process
	MajorFltRate float64 // host-side major faults/s of the hypervisor process
	HugetlbFail  uint64  // cumulative guest hugetlb allocation failures
}

type IfaceStat struct {
	Name     string
	Ifindex  int
	RxBps    float64
	TxBps    float64
	RxPps    float64
	TxPps    float64
	RxErrs   uint64 // cumulative
	TxErrs   uint64
	RxDrops  uint64
	TxDrops  uint64
	DropRate float64 // host-side drops/s (rx+tx), libvirt counters or eBPF
}

type DiskStat struct {
	Dev       string
	RdBps     float64
	WrBps     float64
	RdIOPS    float64
	WrIOPS    float64
	ErrsTotal int64 // -1 when the hypervisor does not report errors
}

type KVMStat struct {
	Available     bool
	ExitRate      float64            // total exits/s
	ExitReasons   map[string]float64 // decoded exit reason -> exits/s
	UserExits     map[string]float64 // KVM_EXIT_* -> exits/s
	IRQRate       float64
	ExceptionRate float64
	EmulFailTotal uint64
	RunqP99Us     float64 // worst vCPU p99
}

type MigrationStat struct {
	Status         string // active | completed | failed | cancelled
	Operation      string
	ElapsedMs      uint64
	MemTotal       uint64
	MemProcessed   uint64
	MemRemaining   uint64
	DirtyPageRate  uint64 // pages/s
	Bps            uint64
	ExpectedDownMs uint64
}

func (d *DomainSnapshot) Running() bool { return d.State == "running" }

func (d *DomainSnapshot) CPUPercent() float64 {
	var t float64
	for _, v := range d.VCPUs {
		t += v.CPUPercent
	}
	return t
}

func (d *DomainSnapshot) NetRates() (rx, tx float64) {
	for _, i := range d.Ifaces {
		rx += i.RxBps
		tx += i.TxBps
	}
	return
}

func (d *DomainSnapshot) DiskRates() (rd, wr float64) {
	for _, k := range d.Disks {
		rd += k.RdBps
		wr += k.WrBps
	}
	return
}

func (d *DomainSnapshot) clone() DomainSnapshot {
	c := *d
	c.VCPUs = append([]VCPUStat(nil), d.VCPUs...)
	c.Ifaces = append([]IfaceStat(nil), d.Ifaces...)
	c.Disks = append([]DiskStat(nil), d.Disks...)
	c.KVM.ExitReasons = cloneMap(d.KVM.ExitReasons)
	c.KVM.UserExits = cloneMap(d.KVM.UserExits)
	if d.Migration != nil {
		m := *d.Migration
		c.Migration = &m
	}
	return c
}

func cloneMap(m map[string]float64) map[string]float64 {
	if m == nil {
		return nil
	}
	c := make(map[string]float64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

type DomainHistory struct {
	CPU      []float64
	RX       []float64
	TX       []float64
	DiskRd   []float64
	DiskWr   []float64
	ExitRate []float64
	RunqP99  []float64
}

type domainEntry struct {
	latest   DomainSnapshot
	cpu      *RingBuffer[float64]
	rx       *RingBuffer[float64]
	tx       *RingBuffer[float64]
	diskRd   *RingBuffer[float64]
	diskWr   *RingBuffer[float64]
	exitRate *RingBuffer[float64]
	runqP99  *RingBuffer[float64]
}

func newEntry() *domainEntry {
	return &domainEntry{
		cpu:      NewRingBuffer[float64](HistoryLen),
		rx:       NewRingBuffer[float64](HistoryLen),
		tx:       NewRingBuffer[float64](HistoryLen),
		diskRd:   NewRingBuffer[float64](HistoryLen),
		diskWr:   NewRingBuffer[float64](HistoryLen),
		exitRate: NewRingBuffer[float64](HistoryLen),
		runqP99:  NewRingBuffer[float64](HistoryLen),
	}
}

// DomainStore holds the latest snapshot and history of every known VM.
// Collectors mutate snapshots in place during a tick; Commit then records
// one history sample per domain.
type DomainStore struct {
	mu       sync.RWMutex
	domains  map[DomainID]*domainEntry
	host     HostStat
	hostHist hostHistory
}

func NewDomainStore() *DomainStore {
	return &DomainStore{
		domains:  make(map[DomainID]*domainEntry),
		hostHist: newHostHistory(),
	}
}

// Upsert creates the domain if needed and applies fn to its snapshot.
func (s *DomainStore) Upsert(id DomainID, fn func(*DomainSnapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.domains[id]
	if !ok {
		e = newEntry()
		e.latest.ID = id
		s.domains[id] = e
	}
	fn(&e.latest)
}

// Mutate applies fn to an existing domain; it is a no-op for unknown IDs.
func (s *DomainStore) Mutate(id DomainID, fn func(*DomainSnapshot)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.domains[id]
	if !ok {
		return false
	}
	fn(&e.latest)
	return true
}

// Retain drops every domain whose ID is not in keep.
func (s *DomainStore) Retain(keep map[DomainID]bool) []DomainID {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed []DomainID
	for id := range s.domains {
		if !keep[id] {
			delete(s.domains, id)
			removed = append(removed, id)
		}
	}
	return removed
}

// Commit records one history sample for every domain.
func (s *DomainStore) Commit(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.domains {
		d := &e.latest
		d.CollectedAt = now
		e.cpu.Push(d.CPUPercent())
		rx, tx := d.NetRates()
		e.rx.Push(rx)
		e.tx.Push(tx)
		rd, wr := d.DiskRates()
		e.diskRd.Push(rd)
		e.diskWr.Push(wr)
		e.exitRate.Push(d.KVM.ExitRate)
		e.runqP99.Push(d.KVM.RunqP99Us)
	}
	s.hostHist.push(&s.host)
}

// Snapshot returns deep copies of all domains sorted by name.
func (s *DomainStore) Snapshot() []DomainSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snaps := make([]DomainSnapshot, 0, len(s.domains))
	for _, e := range s.domains {
		snaps = append(snaps, e.latest.clone())
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Name < snaps[j].Name })
	return snaps
}

func (s *DomainStore) Get(id DomainID) (DomainSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.domains[id]
	if !ok {
		return DomainSnapshot{}, false
	}
	return e.latest.clone(), true
}

func (s *DomainStore) History(id DomainID) DomainHistory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.domains[id]
	if !ok {
		return DomainHistory{}
	}
	return DomainHistory{
		CPU:      e.cpu.Slice(),
		RX:       e.rx.Slice(),
		TX:       e.tx.Slice(),
		DiskRd:   e.diskRd.Slice(),
		DiskWr:   e.diskWr.Slice(),
		ExitRate: e.exitRate.Slice(),
		RunqP99:  e.runqP99.Slice(),
	}
}
