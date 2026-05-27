// internal/collect/ebpf.go
//go:build linux

package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"hyperview/internal/bpf"
	"hyperview/internal/store"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/procfs"
)

type EBPFCollector struct {
	mu          sync.Mutex
	objs        bpf.KvmEventsObjects
	links       []link.Link
	enabled     bool
	errStatus   string
	pidToDomID  map[uint32]string
	prevExits   map[uint32]uint64            // Tracks host-wide historical totals to compute deltas
	domainExits map[string]map[uint32]uint64 // Tracks persistent cumulative exits per domain ID
}

func NewEBPFCollector() *EBPFCollector {
	ec := &EBPFCollector{
		pidToDomID:  make(map[uint32]string),
		prevExits:   make(map[uint32]uint64),
		domainExits: make(map[string]map[uint32]uint64),
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		ec.errStatus = fmt.Sprintf("rlimit memory unlock fail: %v", err)
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}

	if err := probeSupport(); err != nil {
		ec.errStatus = err.Error()
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}

	var objs bpf.KvmEventsObjects
	if err := bpf.LoadKvmEventsObjects(&objs, nil); err != nil {
		ec.errStatus = fmt.Sprintf("kernel object load error: %v", err)
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}

	// Attach using high-efficiency Raw Links to bypass system tracefs permission layers safely
	l1, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "kvm_exit",
		Program: objs.HandleKvmExit,
	})
	if err != nil {
		objs.Close()
		ec.errStatus = fmt.Sprintf("raw exit tracepoint link hook fail: %v", err)
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}
	ec.links = append(ec.links, l1)

	ec.objs = objs
	ec.enabled = true
	slog.Info("eBPF raw architecture kernel link engine cleanly deployed")
	return ec
}

func (ec *EBPFCollector) Name() string { return "ebpf" }

func (ec *EBPFCollector) Close() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	for _, l := range ec.links {
		if l != nil {
			_ = l.Close()
		}
	}
	return ec.objs.Close()
}

func (ec *EBPFCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	if !ec.enabled {
		return nil
	}

	snapshots := s.Snapshot()
	activePIDs := make(map[uint32]bool)

	for _, snap := range snapshots {
		if snap.State == "running" {
			pid, err := findPidForDomain(snap.Name)
			if err == nil {
				qemuPID := uint32(pid)
				ec.pidToDomID[qemuPID] = snap.ID
				activePIDs[qemuPID] = true

				one := uint8(1)
				_ = ec.objs.TargetPids.Update(&qemuPID, &one, ebpf.UpdateAny)
			}
		}
	}

	for pid, domID := range ec.pidToDomID {
		if !activePIDs[pid] {
			_ = ec.objs.TargetPids.Delete(&pid)
			delete(ec.pidToDomID, pid)
			delete(ec.domainExits, domID)
		}
	}

	numCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		numCPUs = 1
	}

	liveExits := make(map[uint32]uint64)
	var reasonKey uint32
	cpuCounts := make([]uint64, numCPUs)

	iterator := ec.objs.ExitCounts.Iterate()
	for iterator.Next(&reasonKey, &cpuCounts) {
		var sum uint64
		for _, coreCount := range cpuCounts {
			sum += coreCount
		}
		liveExits[reasonKey] = sum
	}

	deltas := make(map[uint32]uint64)
	for r, currentTotal := range liveExits {
		oldTotal := ec.prevExits[r]
		if currentTotal >= oldTotal {
			deltas[r] = currentTotal - oldTotal
		}
		ec.prevExits[r] = currentTotal
	}

	for _, domID := range ec.pidToDomID {
		if _, ok := ec.domainExits[domID]; !ok {
			ec.domainExits[domID] = make(map[uint32]uint64)
		}

		for r, countDelta := range deltas {
			if countDelta > 0 {
				ec.domainExits[domID][r] += countDelta
			}
		}

		for _, snap := range snapshots {
			if snap.ID == domID {
				snap.KVMEvents.Available = true
				snap.KVMEvents.ExitReasons = make(map[uint32]uint64)

				// STRICTLY POPULATE MAP RECORD VALUES FROM THE REAL MEASURED KERNEL HISTOGRAM ONLY
				for r, totalCount := range ec.domainExits[domID] {
					if totalCount > 0 {
						snap.KVMEvents.ExitReasons[r] = totalCount
					}
				}

				s.Update(snap)
			}
		}
	}
	return nil
}

func probeSupport() error {
	if os.Geteuid() != 0 {
		return errors.New("requires root privileges")
	}
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	if os.IsNotExist(err) {
		return errors.New("missing BTF layout format configuration")
	}
	return nil
}

// Upgraded to precise tokenized parameter scanning to avoid helper process pollution
func findPidForDomain(domainName string) (int, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return 0, err
	}
	procs, err := fs.AllProcs()
	if err != nil {
		return 0, err
	}

	for _, p := range procs {
		cmdline, err := p.CmdLine()
		if err != nil {
			continue
		}

		isQemu := false
		isTargetDomain := false
		for i, arg := range cmdline {
			if strings.Contains(arg, "qemu") {
				isQemu = true
			}
			if (arg == "-name" || arg == "-domain") && i+1 < len(cmdline) {
				if strings.HasPrefix(cmdline[i+1], "guest="+domainName+",") || cmdline[i+1] == domainName {
					isTargetDomain = true
				}
			}
		}

		if isQemu && isTargetDomain {
			return p.PID, nil
		}
	}

	return 0, os.ErrNotExist
}
