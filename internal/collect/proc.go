// internal/collect/proc.go
package collect

import (
	"context"
	"os"
	"strings"
	"sync"

	"hyperview/internal/store"

	"github.com/prometheus/procfs"
)

type ProcCollector struct {
	mu       sync.Mutex
	fs       procfs.FS
	pidCache map[string]int
}

func NewProcCollector() (*ProcCollector, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}
	return &ProcCollector{
		fs:       fs,
		pidCache: make(map[string]int),
	}, nil
}

func (pc *ProcCollector) Name() string { return "proc" }
func (pc *ProcCollector) Close() error { return nil }

func (pc *ProcCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	snapshots := s.Snapshot()
	for _, snap := range snapshots {
		pid, err := pc.findOrCreatePid(snap.Name)
		if err != nil {
			continue
		}

		proc, err := pc.fs.Proc(pid)
		if err != nil {
			delete(pc.pidCache, snap.Name)
			continue
		}

		stat, err := proc.Stat()
		if err != nil {
			continue
		}

		snap.Mem.MinorFaults = uint64(stat.MinFlt)
		snap.Mem.MajorFaults = uint64(stat.MajFlt)
		snap.Mem.RssKiB = uint64(stat.ResidentMemory() / 1024)

		s.Update(snap)
	}
	return nil
}

func (pc *ProcCollector) findOrCreatePid(domainName string) (int, error) {
	if pid, exists := pc.pidCache[domainName]; exists {
		return pid, nil
	}

	procs, err := pc.fs.AllProcs()
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
			pc.pidCache[domainName] = p.PID
			return p.PID, nil
		}
	}
	return 0, os.ErrNotExist
}
