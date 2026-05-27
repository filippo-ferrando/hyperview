package store

import (
	"sync"
	"time"
)

type DomainID = string

type DomainSnapshot struct {
	ID          DomainID
	Name        string
	State       string
	VCPUs       []VCPUStat
	Mem         MemStat
	Ifaces      []IfaceStat
	Disks       []DiskStat
	KVMEvents   KVMEventStat
	Migration   *MigrationStat
	CollectedAt time.Time
}

type VCPUStat struct {
	Index      int
	CPUPercent float64
	RunCount   uint64
	WaitNs     uint64
}

type MemStat struct {
	AllocKiB     uint64
	AvailableKiB uint64
	RssKiB       uint64
	MinorFaults  uint64
	MajorFaults  uint64
}

type IfaceStat struct {
	Name    string
	RxBytes uint64
	TxBytes uint64
	RxPkts  uint64
	TxPkts  uint64
}

type DiskStat struct {
	Dev     string
	RdBytes uint64
	WrBytes uint64
	RdReqs  uint64
	WrReqs  uint64
}

type KVMEventStat struct {
	Available     bool
	ExitReasons   map[uint32]uint64
	IRQInjections uint64
	HaltPollNs    uint64
	MMIOExits     uint64
}

type MigrationStat struct {
	Status         string
	TotalPages     uint64
	DirtyPages     uint64
	DirtyPageRate  uint64
	MbpsDown       float64
	ExpectedDownMs uint64
	TotalTimeMs    uint64
}

type DomainHistory struct {
	CPU []float64
	RX  []uint64
	TX  []uint64
}

type DomainStore struct {
	mu      sync.RWMutex
	domains map[DomainID]*domainEntry
}

type domainEntry struct {
	latest  DomainSnapshot
	cpuHist *RingBuffer[float64]
	rxHist  *RingBuffer[uint64]
	txHist  *RingBuffer[uint64]
}

func NewDomainStore() *DomainStore {
	return &DomainStore{
		domains: make(map[DomainID]*domainEntry),
	}
}

func (s *DomainStore) Update(snap DomainSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.domains[snap.ID]
	if !exists {
		entry = &domainEntry{
			cpuHist: NewRingBuffer[float64](60),
			rxHist:  NewRingBuffer[uint64](60),
			txHist:  NewRingBuffer[uint64](60),
		}
		s.domains[snap.ID] = entry
	}

	if len(snap.Ifaces) == 0 && len(entry.latest.Ifaces) > 0 {
		snap.Ifaces = entry.latest.Ifaces
	}
	if len(snap.Disks) == 0 && len(entry.latest.Disks) > 0 {
		snap.Disks = entry.latest.Disks
	}
	if len(snap.VCPUs) == 0 && len(entry.latest.VCPUs) > 0 {
		snap.VCPUs = entry.latest.VCPUs
	}
	if snap.Mem.AllocKiB == 0 && entry.latest.Mem.AllocKiB > 0 {
		snap.Mem.AllocKiB = entry.latest.Mem.AllocKiB
		snap.Mem.AvailableKiB = entry.latest.Mem.AvailableKiB
	}

	if !snap.KVMEvents.Available && entry.latest.KVMEvents.Available {
		snap.KVMEvents = entry.latest.KVMEvents
	}

	if snap.Migration == nil && entry.latest.Migration != nil {
		snap.Migration = entry.latest.Migration
	}

	entry.latest = snap

	var totalCPU float64
	for _, vcpu := range snap.VCPUs {
		totalCPU += vcpu.CPUPercent
	}
	entry.cpuHist.Push(totalCPU)

	var totalRx, totalTx uint64
	for _, iface := range snap.Ifaces {
		totalRx += iface.RxBytes
		totalTx += iface.TxBytes
	}
	entry.rxHist.Push(totalRx)
	entry.txHist.Push(totalTx)
}

func (s *DomainStore) Snapshot() []DomainSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snaps := make([]DomainSnapshot, 0, len(s.domains))
	for _, entry := range s.domains {
		snaps = append(snaps, entry.latest)
	}
	return snaps
}

func (s *DomainStore) Get(id DomainID) (DomainSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.domains[id]
	if !exists {
		return DomainSnapshot{}, false
	}
	return entry.latest, true
}

func (s *DomainStore) History(id DomainID) DomainHistory {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.domains[id]
	if !exists {
		return DomainHistory{}
	}
	return DomainHistory{
		CPU: entry.cpuHist.Slice(),
		RX:  entry.rxHist.Slice(),
		TX:  entry.txHist.Slice(),
	}
}
