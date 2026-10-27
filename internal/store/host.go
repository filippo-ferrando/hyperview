package store

import "time"

// HostStat describes the hypervisor host itself.
type HostStat struct {
	Hostname     string
	Kernel       string
	Arch         string
	CPUs         int
	Uptime       time.Duration
	CPUPercent   float64
	Load1        float64
	MemTotalKiB  uint64
	MemAvailKiB  uint64
	SwapTotalKiB uint64
	SwapFreeKiB  uint64
	PSI          PSIStat
}

// PSIStat holds the avg10 values of /proc/pressure/*; Available is false on
// kernels built without CONFIG_PSI or booted with psi=0.
type PSIStat struct {
	Available bool
	CPUSome   float64
	MemSome   float64
	MemFull   float64
	IOSome    float64
	IOFull    float64
}

func (h *HostStat) MemUsedPercent() float64 {
	if h.MemTotalKiB == 0 {
		return 0
	}
	return 100 * float64(h.MemTotalKiB-h.MemAvailKiB) / float64(h.MemTotalKiB)
}

type HostHistory struct {
	CPU []float64
	Mem []float64
}

type hostHistory struct {
	cpu *RingBuffer[float64]
	mem *RingBuffer[float64]
}

func newHostHistory() hostHistory {
	return hostHistory{
		cpu: NewRingBuffer[float64](HistoryLen),
		mem: NewRingBuffer[float64](HistoryLen),
	}
}

func (h *hostHistory) push(s *HostStat) {
	h.cpu.Push(s.CPUPercent)
	h.mem.Push(s.MemUsedPercent())
}

func (s *DomainStore) SetHost(h HostStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.host = h
}

func (s *DomainStore) Host() HostStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.host
}

func (s *DomainStore) HostHistory() HostHistory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return HostHistory{CPU: s.hostHist.cpu.Slice(), Mem: s.hostHist.mem.Slice()}
}
