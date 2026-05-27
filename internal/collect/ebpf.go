// internal/collect/ebpf.go
//go:build linux

package collect

import (
	"bytes"
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
)

type EBPFCollector struct {
	mu         sync.Mutex
	objs       bpf.KvmEventsObjects
	links      []link.Link
	enabled    bool
	errStatus  string
	pidToDomID map[uint32]string
	prevExits  map[uint32]uint64 // Tracks historical totals to calculate accurate deltas
}

func NewEBPFCollector() *EBPFCollector {
	ec := &EBPFCollector{
		pidToDomID: make(map[uint32]string),
		prevExits:  make(map[uint32]uint64),
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

	// 1. Core Essential Tracepoints (Required for KVM exit stats)
	l1, err := link.Tracepoint("kvm", "kvm_exit", objs.HandleKvmExit, nil)
	if err != nil {
		objs.Close()
		ec.errStatus = fmt.Sprintf("core exit tracepoint hook fail: %v", err)
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}
	ec.links = append(ec.links, l1)

	l2, err := link.Tracepoint("kvm", "kvm_inj_virq", objs.HandleKvmInjVirq, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		ec.errStatus = fmt.Sprintf("core irq tracepoint hook fail: %v", err)
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}
	ec.links = append(ec.links, l2)

	// 2. Optional Advanced Tracepoints & Kprobes (Skip gracefully if missing on host)
	if l3, err := link.Tracepoint("kvm", "kvm_mmu_page_fault", objs.HandleKvmMmuPageFault, nil); err == nil {
		ec.links = append(ec.links, l3)
		slog.Debug("Optional eBPF tracepoint attached", slog.String("name", "kvm_mmu_page_fault"))
	} else {
		slog.Warn("Optional eBPF tracepoint unavailable on this kernel; skipping", slog.String("name", "kvm_mmu_page_fault"))
	}

	if l4, err := link.Tracepoint("kvm", "kvm_halt_poll_ns", objs.HandleKvmHaltPollNs, nil); err == nil {
		ec.links = append(ec.links, l4)
		slog.Debug("Optional eBPF tracepoint attached", slog.String("name", "kvm_halt_poll_ns"))
	} else {
		slog.Warn("Optional eBPF tracepoint unavailable on this kernel; skipping", slog.String("name", "kvm_halt_poll_ns"))
	}

	if l5, err := link.Kprobe("handle_mm_fault", objs.HandleMmFaultKprobe, nil); err == nil {
		ec.links = append(ec.links, l5)
		slog.Debug("Optional eBPF kprobe attached", slog.String("name", "handle_mm_fault"))
	} else {
		slog.Warn("Optional eBPF kprobe unavailable or blocked on this kernel; skipping", slog.String("name", "handle_mm_fault"))
	}

	if l6, err := link.Tracepoint("kvm", "kvm_dirty_ring_push", objs.HandleKvmDirtyRingPush, nil); err == nil {
		ec.links = append(ec.links, l6)
		slog.Debug("Optional eBPF tracepoint attached", slog.String("name", "kvm_dirty_ring_push"))
	} else {
		slog.Debug("Optional eBPF tracepoint unavailable on this kernel; skipping", slog.String("name", "kvm_dirty_ring_push"))
	}

	ec.objs = objs
	ec.enabled = true
	slog.Info("eBPF hardware virtualization monitoring layer online")
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

	for pid := range ec.pidToDomID {
		if !activePIDs[pid] {
			_ = ec.objs.TargetPids.Delete(&pid)
			delete(ec.pidToDomID, pid)
		}
	}

	// 1. Iterate through the live PerCPU kernel hash map to pull all hardware exit events
	liveExits := make(map[uint32]uint64)
	var (
		reasonKey uint32
		cpuCounts []uint64
	)
	iterator := ec.objs.ExitCounts.Iterate()
	for iterator.Next(&reasonKey, &cpuCounts) {
		var sum uint64
		for _, coreCount := range cpuCounts {
			sum += coreCount
		}
		liveExits[reasonKey] = sum
	}

	// 2. Compute accurate deltas per refresh frame interval
	deltas := make(map[uint32]uint64)
	for r, currentTotal := range liveExits {
		oldTotal := ec.prevExits[r]
		if currentTotal >= oldTotal {
			deltas[r] = currentTotal - oldTotal
		}
		ec.prevExits[r] = currentTotal
	}

	// 3. Update the storage engine snapshot records with verified data
	for _, domID := range ec.pidToDomID {
		for _, snap := range snapshots {
			if snap.ID == domID {
				snap.KVMEvents.Available = true
				snap.KVMEvents.ExitReasons = make(map[uint32]uint64)

				// Bind all non-zero operational exit reason deltas to the layout box
				for r, countDelta := range deltas {
					if countDelta > 0 {
						snap.KVMEvents.ExitReasons[r] = countDelta
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

func findPidForDomain(name string) (int, error) {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(f.Name(), "%d", &pid); err != nil {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		sCmd := string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '}))
		if strings.Contains(sCmd, "qemu") && strings.Contains(sCmd, name) {
			return pid, nil
		}
	}
	return 0, os.ErrNotExist
}
