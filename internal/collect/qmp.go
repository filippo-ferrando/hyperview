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
	}
}

func (qc *QMPCollector) Name() string { return "qmp" }
func (qc *QMPCollector) Close() error { return nil }

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
		if err != nil {
			// If not migrating or socket doesn't respond, ensure stats stay strictly nil
			snap.Migration = nil
			s.Update(snap)
			continue
		}

		if migrationData != nil {
			snap.Migration = migrationData
			s.Update(snap)
		} else {
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

	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)

	capCmd, _ := json.Marshal(qmpCommand{Execute: "qmp_capabilities"})
	_, _ = conn.Write(append(capCmd, '\n'))
	_, _ = conn.Read(buf)

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
