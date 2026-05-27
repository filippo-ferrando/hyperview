package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"hyperview/internal/store"
)

type QMPCollector struct {
	mu             sync.Mutex
	baseMonitorDir string
	simulatedProg  map[string]uint64
}

type qmpCommand struct {
	Execute string `json:"execute"`
}

type qmpMigrationResponse struct {
	Return struct {
		Status       string `json:"status"`
		TotalTime    uint64 `json:"total-time"`
		ExpectedDown uint64 `json:"expected-downtime"`
		Ram          struct {
			Total     uint64 `json:"total"`
			Duplicate uint64 `json:"duplicate"`
			Remaining uint64 `json:"remaining"`
			Rate      uint64 `json:"dirty-pages-rate"`
		} `json:"ram"`
	} `json:"return"`
}

func NewQMPCollector(baseMonitorDir string) *QMPCollector {
	return &QMPCollector{
		baseMonitorDir: baseMonitorDir,
		simulatedProg:  make(map[string]uint64),
	}
}

func (qc *QMPCollector) Name() string { return "qmp" }
func (qc *QMPCollector) Close() error { return nil }

// internal/collect/qmp.go

func (qc *QMPCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	snapshots := s.Snapshot()
	for _, snap := range snapshots {
		if snap.State != "running" && snap.State != "paused" {
			continue
		}

		sockPath := fmt.Sprintf("%s/%s.monitor", qc.baseMonitorDir, snap.Name)
		migrationData, err := qc.queryQMPSocket(sockPath)
		// REMOVE OR COMMENT OUT THE SIMULATION FALLBACK:
		if err != nil {
			// Clear any old migration data if the socket connection is absent or drops
			snap.Migration = nil
			s.Update(snap)
			continue
		}

		if migrationData != nil {
			snap.Migration = migrationData
			s.Update(snap)
		} else {
			// Clear state if query-migrate explicitly indicates status is "none" or completed
			snap.Migration = nil
			s.Update(snap)
		}
	}
	return nil
}

func (qc *QMPCollector) queryQMPSocket(sockPath string) (*store.MigrationStat, error) {
	conn, err := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Handle the initial greeting banner from QEMU
	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)

	// Issue mandatory capabilities negotiation command
	capCmd, _ := json.Marshal(qmpCommand{Execute: "qmp_capabilities"})
	_, _ = conn.Write(append(capCmd, '\n'))
	_, _ = conn.Read(buf)

	// Poll migration statistics
	migCmd, _ := json.Marshal(qmpCommand{Execute: "query-migrate"})
	_, _ = conn.Write(append(migCmd, '\n'))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var resp qmpMigrationResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil || resp.Return.Status == "" {
		return nil, fmt.Errorf("invalid json-rpc packet")
	}

	if resp.Return.Status == "none" || resp.Return.Status == "completed" {
		return nil, nil
	}

	return &store.MigrationStat{
		Status:         resp.Return.Status,
		TotalPages:     resp.Return.Ram.Total / 4096,
		DirtyPages:     resp.Return.Ram.Remaining / 4096,
		DirtyPageRate:  resp.Return.Ram.Rate,
		MbpsDown:       float64(resp.Return.Ram.Total-resp.Return.Ram.Remaining) * 8 / 1000000.0,
		ExpectedDownMs: resp.Return.ExpectedDown,
		TotalTimeMs:    resp.Return.TotalTime,
	}, nil
}

func (qc *QMPCollector) generateSimulationTelemetry(name string) *store.MigrationStat {
	prog, ok := qc.simulatedProg[name]
	if !ok {
		// Initialize dummy loop if no reference is present
		qc.simulatedProg[name] = 0
		prog = 0
	}

	if prog >= 100 {
		// Reset tracking once completed
		qc.simulatedProg[name] = 0
		return nil
	}

	qc.simulatedProg[name] += 1
	totalPages := uint64(262144) // Represents a standard 1 GiB allocation footprint
	dirtyPages := totalPages - ((totalPages * prog) / 100)

	return &store.MigrationStat{
		Status:         "active",
		TotalPages:     totalPages,
		DirtyPages:     dirtyPages,
		DirtyPageRate:  420,
		MbpsDown:       850.5,
		ExpectedDownMs: 15,
		TotalTimeMs:    prog * 250,
	}
}
