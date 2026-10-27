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
	"sync"

	"hyperview/internal/bpf"
	"hyperview/internal/store"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
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
}

func NewEBPFCollector() *EBPFCollector {
	ec := &EBPFCollector{
		pidToDomID:  make(map[uint32]string),
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
		if snap.PID > 0 && snap.Running() {
			pid := uint32(snap.PID)
			ec.pidToDomID[pid] = snap.ID
			activePIDs[pid] = true
			one := uint8(1)
			_ = ec.objs.TargetPids.Update(&pid, &one, ebpf.UpdateAny)
		}
	}
	for pid := range ec.pidToDomID {
		if !activePIDs[pid] {
			_ = ec.objs.TargetPids.Delete(&pid)
			delete(ec.pidToDomID, pid)
		}
	}

	for _, snap := range snapshots {
		if !activePIDs[uint32(snap.PID)] {
			continue
		}
		s.Mutate(snap.ID, func(d *store.DomainSnapshot) {
			d.KVM.Available = true
			for i := range d.VCPUs {
				tid := uint32(d.VCPUs[i].TID)
				var metric struct {
					ExitCount   uint64
					LastExitTs  uint64
					TotalWaitNs uint64
				}
				if tid != 0 && ec.objs.VcpuStats.Lookup(&tid, &metric) == nil {
					d.VCPUs[i].ExitRate = float64(metric.ExitCount)
				}
			}
		})
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

