package collect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"hyperview/internal/store"
)

// ScanCollector reports KVM processes that no other discoverer owns
// (plain QEMU, Proxmox, Firecracker, cloud-hypervisor, ...). Network stats
// come from the tap devices, disk throughput from /proc/<pid>/io.
type ScanCollector struct {
	mu      sync.Mutex
	index   *ProcessIndex
	claimed func() map[int]bool
	rates   *rateTracker
	alive   []store.DomainID
	sysNet  string
}

// NewScanCollector skips every PID returned by claimed, typically the
// processes already reported by libvirt.
func NewScanCollector(index *ProcessIndex, claimed func() map[int]bool) *ScanCollector {
	return &ScanCollector{index: index, claimed: claimed, rates: newRateTracker(), sysNet: "/sys/class/net"}
}

func (sc *ScanCollector) Name() string            { return "kvmscan" }
func (sc *ScanCollector) Close() error            { return nil }
func (sc *ScanCollector) Alive() []store.DomainID { return sc.alive }

func (sc *ScanCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	now := time.Now()
	sc.index.Refresh(now)
	claimed := map[int]bool{}
	if sc.claimed != nil {
		claimed = sc.claimed()
	}

	sc.alive = nil
	for _, p := range sc.index.All() {
		if claimed[p.PID] {
			continue
		}
		id := store.DomainID(fmt.Sprintf("pid-%d-%d", p.PID, p.Start))
		sc.alive = append(sc.alive, id)

		ifaces := sc.tapStats(id, p.Taps, now)
		disk := sc.processIO(id, p.PID, now)

		s.Upsert(id, func(d *store.DomainSnapshot) {
			d.Name, d.UUID, d.Source, d.PID = p.Name, p.UUID, p.Source, p.PID
			d.State = "running"
			d.Mem.MaxKiB = p.MemMiB * 1024
			d.Ifaces = ifaces
			d.Disks = disk
		})
	}
	sc.rates.sweep()
	return nil
}

// tapStats reads tap counters. A tap's TX is the guest's RX, so directions
// are swapped to present them from the guest's point of view like libvirt.
func (sc *ScanCollector) tapStats(id store.DomainID, taps []string, now time.Time) []store.IfaceStat {
	var out []store.IfaceStat
	for _, tap := range taps {
		dir := filepath.Join(sc.sysNet, tap)
		read := func(name string) uint64 { return readUint(filepath.Join(dir, "statistics", name)) }
		k := string(id) + "/" + tap
		rxB, txB := read("tx_bytes"), read("rx_bytes")
		rxP, txP := read("tx_packets"), read("rx_packets")
		rxD, txD := read("tx_dropped"), read("rx_dropped")
		out = append(out, store.IfaceStat{
			Name:     tap,
			Ifindex:  int(readUint(filepath.Join(dir, "ifindex"))),
			RxBps:    sc.rates.rate(k+"/rxb", float64(rxB), now),
			TxBps:    sc.rates.rate(k+"/txb", float64(txB), now),
			RxPps:    sc.rates.rate(k+"/rxp", float64(rxP), now),
			TxPps:    sc.rates.rate(k+"/txp", float64(txP), now),
			RxErrs:   read("tx_errors"),
			TxErrs:   read("rx_errors"),
			RxDrops:  rxD,
			TxDrops:  txD,
			DropRate: sc.rates.rate(k+"/drop", float64(rxD+txD), now),
		})
	}
	return out
}

// processIO reports the block-layer bytes of the whole hypervisor process,
// as per-disk stats need the hypervisor's own monitor API.
func (sc *ScanCollector) processIO(id store.DomainID, pid int, now time.Time) []store.DiskStat {
	f, err := os.Open(fmt.Sprintf("/proc/%d/io", pid))
	if err != nil {
		return nil
	}
	defer f.Close()
	var rd, wr uint64
	sn := bufio.NewScanner(f)
	for sn.Scan() {
		k, v, ok := strings.Cut(sn.Text(), ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		switch k {
		case "read_bytes":
			rd = n
		case "write_bytes":
			wr = n
		}
	}
	k := string(id) + "/io"
	return []store.DiskStat{{
		Dev:       "(all)",
		RdBps:     sc.rates.rate(k+"/rd", float64(rd), now),
		WrBps:     sc.rates.rate(k+"/wr", float64(wr), now),
		ErrsTotal: -1,
	}}
}

func readUint(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}
