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
	"github.com/prometheus/procfs"
)

type EBPFCollector struct {
	mu          sync.Mutex
	objs        bpf.KvmEventsObjects
	links       []link.Link
	enabled     bool
	errStatus   string
	pidToDomID  map[uint32]string
	domainExits map[string]map[uint32]uint64 // FIX: Clean type declaration without 'make'
}

func NewEBPFCollector() *EBPFCollector {
	ec := &EBPFCollector{
		pidToDomID:  make(map[uint32]string),
		domainExits: make(map[string]map[uint32]uint64), // Initialized correctly here
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		ec.errStatus = fmt.Sprintf("rlimit unlock fail: %v", err)
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

	// Attach raw exit link
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

	// Attach raw entry link
	l2, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "kvm_entry",
		Program: objs.HandleKvmEntry,
	})
	if err != nil {
		l1.Close()
		objs.Close()
		ec.errStatus = fmt.Sprintf("raw entry tracepoint link hook fail: %v", err)
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}
	ec.links = append(ec.links, l2)

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

	// 1. Iterate through the global Hash map directly into our tracker cache
	var (
		reasonKey uint32
		exitCount uint64
	)
	iterator := ec.objs.ExitCounts.Iterate()
	for iterator.Next(&reasonKey, &exitCount) {
		for _, domID := range ec.pidToDomID {
			if ec.domainExits[domID] == nil {
				ec.domainExits[domID] = make(map[uint32]uint64)
			}
			if exitCount > 0 {
				ec.domainExits[domID][reasonKey] = exitCount
			}
		}
	}

	// 2. Stream real, un-falsified counters into the domain store
	for mainPID, domID := range ec.pidToDomID {
		for _, snap := range snapshots {
			if snap.ID == domID {
				snap.KVMEvents.Available = true
				snap.KVMEvents.ExitReasons = make(map[uint32]uint64)

				for r, totalCount := range ec.domainExits[domID] {
					if totalCount > 0 {
						snap.KVMEvents.ExitReasons[r] = totalCount
					}
				}

				// Read real thread identities matching "CPU <n>/KVM" to fix core layout mapping shifts
				taskPath := fmt.Sprintf("/proc/%d/task", mainPID)
				entries, err := os.ReadDir(taskPath)
				if err == nil {
					for _, entry := range entries {
						tidStr := entry.Name()
						commBytes, err := os.ReadFile(fmt.Sprintf("%s/%s/comm", taskPath, tidStr))
						if err != nil {
							continue
						}
						comm := string(bytes.TrimSpace(commBytes))

						if strings.HasPrefix(comm, "CPU ") {
							var vcpuIdx int
							_, err := fmt.Sscanf(comm, "CPU %d", &vcpuIdx)
							if err == nil && vcpuIdx >= 0 && vcpuIdx < len(snap.VCPUs) {
								var tid uint32
								if _, err := fmt.Sscanf(tidStr, "%d", &tid); err == nil {
									var metric struct {
										ExitCount   uint64
										LastExitTs  uint64
										TotalWaitNs uint64
									}
									if err := ec.objs.VcpuStats.Lookup(&tid, &metric); err == nil {
										snap.VCPUs[vcpuIdx].RunCount = metric.ExitCount
										snap.VCPUs[vcpuIdx].WaitNs = metric.TotalWaitNs
									}
								}
							}
						}
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
				val := cmdline[i+1]
				if val == domainName || val == "guest="+domainName || strings.HasPrefix(val, "guest="+domainName+",") {
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
