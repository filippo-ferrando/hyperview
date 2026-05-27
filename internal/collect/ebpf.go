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
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

type bpfLink interface {
	Close() error
}

type legacyLink struct {
	fd int
}

func (l *legacyLink) Close() error {
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(l.fd), unix.PERF_EVENT_IOC_DISABLE, 0)
	return unix.Close(l.fd)
}

type EBPFCollector struct {
	mu          sync.Mutex
	objs        bpf.KvmEventsObjects
	links       []bpfLink
	enabled     bool
	errStatus   string
	pidToDomID  map[uint32]string
	domainExits map[string]map[uint32]uint64
}

func NewEBPFCollector() *EBPFCollector {
	ec := &EBPFCollector{
		pidToDomID:  make(map[uint32]string),
		domainExits: make(map[string]map[uint32]uint64),
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

	if err := ec.attachTracepointLegacy("kvm", "kvm_exit", objs.HandleKvmExit); err != nil {
		objs.Close()
		ec.errStatus = fmt.Sprintf("legacy exit tracepoint attachment fail: %v", err)
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}

	if err := ec.attachTracepointLegacy("kvm", "kvm_entry", objs.HandleKvmEntry); err != nil {
		ec.Close()
		objs.Close()
		ec.errStatus = fmt.Sprintf("legacy entry tracepoint attachment fail: %v", err)
		slog.Error("eBPF initialization aborting", slog.String("reason", ec.errStatus))
		return ec
	}

	ec.objs = objs
	ec.enabled = true
	slog.Info("eBPF legacy tracepoint link engine safely deployed")
	return ec
}

func (ec *EBPFCollector) attachTracepointLegacy(category, name string, prog *ebpf.Program) error {
	for _, base := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		idPath := fmt.Sprintf("%s/events/%s/%s/id", base, category, name)
		data, err := os.ReadFile(idPath)
		if err != nil {
			continue
		}
		var id int
		if _, err := fmt.Sscanf(string(bytes.TrimSpace(data)), "%d", &id); err != nil {
			return err
		}

		attr := &unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_TRACEPOINT,
			Config: uint64(id),
		}

		fd, err := unix.PerfEventOpen(attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			return err
		}

		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(prog.FD()))
		if errno != 0 {
			_ = unix.Close(fd)
			return errno
		}

		_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.PERF_EVENT_IOC_ENABLE, 0)
		if errno != 0 {
			_ = unix.Close(fd)
			return errno
		}

		ec.links = append(ec.links, &legacyLink{fd: fd})
		return nil
	}
	return fmt.Errorf("tracepoint source path %s/%s missing", category, name)
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
