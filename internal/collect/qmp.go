package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"hyperview/internal/store"
)

// QMPCollector polls the QMP monitor of QEMU guests that libvirt does not
// manage, for run state (io-error, guest-panicked, ...), per-disk stats and
// migration progress. QMP sockets serve one client at a time, so each poll
// connects, queries and disconnects quickly, and polls run in the
// background so a stuck monitor never delays a tick.
type QMPCollector struct {
	index    *ProcessIndex
	interval time.Duration
	timeout  time.Duration

	mu      sync.Mutex
	results map[store.DomainID]*qmpResult
	polling map[store.DomainID]bool
	tried   map[store.DomainID]bool // first synchronous poll done
	warned  map[string]bool
}

type qmpResult struct {
	at        time.Time
	state     string
	reason    string
	blk       []qmpBlockStats
	disks     []store.DiskStat
	migration *store.MigrationStat
}

func NewQMPCollector(index *ProcessIndex, interval, timeout time.Duration) *QMPCollector {
	return &QMPCollector{
		index: index, interval: interval, timeout: timeout,
		results: make(map[store.DomainID]*qmpResult),
		polling: make(map[store.DomainID]bool),
		tried:   make(map[store.DomainID]bool),
		warned:  make(map[string]bool),
	}
}

func (qc *QMPCollector) Name() string { return "qmp" }
func (qc *QMPCollector) Close() error { return nil }

func (qc *QMPCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	now := time.Now()
	procs := make(map[int]KVMProcess)
	for _, p := range qc.index.All() {
		procs[p.PID] = p
	}

	type target struct {
		id   store.DomainID
		sock string
	}
	var targets, first []target
	for _, d := range s.Snapshot() {
		if d.Source != "qemu" {
			continue
		}
		if p, ok := procs[d.PID]; ok {
			if sock := qmpSocket(p.Cmdline); sock != "" {
				targets = append(targets, target{d.ID, sock})
			}
		}
	}

	// A VM seen for the first time is polled synchronously (bounded by the
	// timeout), so its first snapshot already has the real run state.
	qc.mu.Lock()
	for _, t := range targets {
		if !qc.tried[t.id] && !qc.polling[t.id] {
			qc.tried[t.id] = true
			qc.polling[t.id] = true
			first = append(first, t)
		}
	}
	qc.mu.Unlock()
	var wg sync.WaitGroup
	for _, t := range first {
		wg.Go(func() { qc.poll(ctx, t.id, t.sock) })
	}
	wg.Wait()

	qc.mu.Lock()
	defer qc.mu.Unlock()
	seen := make(map[store.DomainID]bool)
	for _, t := range targets {
		seen[t.id] = true
		r := qc.results[t.id]
		if (r == nil || now.Sub(r.at) >= qc.interval) && !qc.polling[t.id] {
			qc.polling[t.id] = true
			go qc.poll(ctx, t.id, t.sock)
		}
		if r == nil || now.Sub(r.at) > 3*qc.interval {
			continue
		}
		s.Mutate(t.id, func(cur *store.DomainSnapshot) {
			cur.State, cur.Reason = r.state, r.reason
			if len(r.disks) > 0 {
				cur.Disks = r.disks
			}
			cur.Migration = r.migration
		})
	}
	for id := range qc.tried {
		if !seen[id] && !qc.polling[id] {
			delete(qc.results, id)
			delete(qc.tried, id)
		}
	}
	return nil
}

func (qc *QMPCollector) poll(ctx context.Context, id store.DomainID, sock string) {
	r, err := qc.query(ctx, sock)
	qc.mu.Lock()
	defer qc.mu.Unlock()
	delete(qc.polling, id)
	if err != nil {
		if !qc.warned[sock] {
			qc.warned[sock] = true
			slog.Warn("QMP poll failed", slog.String("socket", sock), slog.Any("err", err))
		}
		return
	}
	delete(qc.warned, sock)
	r.disks = blockRates(qc.results[id], r)
	qc.results[id] = r
}

// blockRates computes per-disk rates between two polls.
func blockRates(prev, cur *qmpResult) []store.DiskStat {
	old := make(map[string]qmpBlockStats)
	if prev != nil {
		for _, b := range prev.blk {
			old[b.name()] = b
		}
	}
	rate := func(c, p uint64) float64 {
		dt := cur.at.Sub(prev.at).Seconds()
		if c < p || dt <= 0 {
			return 0
		}
		return float64(c-p) / dt
	}
	var out []store.DiskStat
	for _, b := range cur.blk {
		name := b.name()
		if name == "" {
			continue
		}
		st := b.Stats
		d := store.DiskStat{Dev: name, ErrsTotal: st.FailedRd + st.FailedWr + st.FailedFlush}
		if o, ok := old[name]; ok {
			d.RdBps = rate(st.RdBytes, o.Stats.RdBytes)
			d.WrBps = rate(st.WrBytes, o.Stats.WrBytes)
			d.RdIOPS = rate(st.RdOps, o.Stats.RdOps)
			d.WrIOPS = rate(st.WrOps, o.Stats.WrOps)
		}
		out = append(out, d)
	}
	return out
}

func (qc *QMPCollector) query(ctx context.Context, sock string) (*qmpResult, error) {
	ctx, cancel := context.WithTimeout(ctx, qc.timeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)

	c := &qmpConn{w: conn, r: bufio.NewReader(conn)}
	if _, err := c.r.ReadBytes('\n'); err != nil { // greeting
		return nil, err
	}
	if err := c.exec("qmp_capabilities", nil); err != nil {
		return nil, err
	}

	var status struct {
		Running bool   `json:"running"`
		Status  string `json:"status"`
	}
	if err := c.exec("query-status", &status); err != nil {
		return nil, err
	}
	r := &qmpResult{at: time.Now()}
	r.state, r.reason = qmpState(status.Status)

	var block []struct {
		Device   string          `json:"device"`
		QDev     string          `json:"qdev"`
		Inserted json.RawMessage `json:"inserted"`
	}
	var stats []qmpBlockStats
	if c.exec("query-block", &block) == nil && c.exec("query-blockstats", &stats) == nil {
		// Skip empty drives (CD-ROM, floppy without media).
		withMedia := make(map[string]bool)
		for _, b := range block {
			if b.Inserted != nil {
				withMedia[b.Device+"|"+b.QDev] = true
			}
		}
		for _, st := range stats {
			if withMedia[st.Device+"|"+st.QDev] {
				r.blk = append(r.blk, st)
			}
		}
	}

	var mig qmpMigrate
	if err := c.exec("query-migrate", &mig); err == nil && mig.Status != "" && mig.Status != "none" {
		st := mig.Status
		switch st {
		case "completed", "failed", "cancelled":
		default:
			st = "active"
		}
		r.migration = &store.MigrationStat{
			Status: st, Operation: "migration-out",
			ElapsedMs:      mig.TotalTime,
			MemTotal:       mig.RAM.Total,
			MemProcessed:   mig.RAM.Transferred,
			MemRemaining:   mig.RAM.Remaining,
			DirtyPageRate:  mig.RAM.DirtyPagesRate,
			Bps:            uint64(mig.RAM.Mbps * 1e6 / 8),
			ExpectedDownMs: mig.ExpectedDowntime,
		}
	}
	return r, nil
}

type qmpConn struct {
	w net.Conn
	r *bufio.Reader
}

// exec runs one command and decodes its "return" into out, skipping
// asynchronous events.
func (c *qmpConn) exec(cmd string, out any) error {
	if _, err := fmt.Fprintf(c.w, `{"execute":%q}`+"\n", cmd); err != nil {
		return err
	}
	for {
		line, err := c.r.ReadBytes('\n')
		if err != nil {
			return err
		}
		var resp struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			Event string `json:"event"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			return err
		}
		switch {
		case resp.Event != "":
			continue
		case resp.Error != nil:
			return fmt.Errorf("%s: %s", cmd, resp.Error.Desc)
		case resp.Return == nil:
			return errors.New(cmd + ": empty response")
		}
		if out == nil {
			return nil
		}
		return json.Unmarshal(resp.Return, out)
	}
}

type qmpBlockStats struct {
	Device   string `json:"device"`
	QDev     string `json:"qdev"`
	NodeName string `json:"node-name"`
	Stats    struct {
		RdBytes     uint64 `json:"rd_bytes"`
		WrBytes     uint64 `json:"wr_bytes"`
		RdOps       uint64 `json:"rd_operations"`
		WrOps       uint64 `json:"wr_operations"`
		FailedRd    int64  `json:"failed_rd_operations"`
		FailedWr    int64  `json:"failed_wr_operations"`
		FailedFlush int64  `json:"failed_flush_operations"`
	} `json:"stats"`
}

// name prefers the legacy drive id, then the device id from the qdev path
// ("/machine/peripheral/virtio-disk0/virtio-backend"), then the node name.
func (b *qmpBlockStats) name() string {
	if b.Device != "" {
		return b.Device
	}
	if rest, ok := strings.CutPrefix(b.QDev, "/machine/peripheral/"); ok {
		id, _, _ := strings.Cut(rest, "/")
		return id
	}
	if b.QDev != "" {
		return b.QDev
	}
	return b.NodeName
}

type qmpMigrate struct {
	Status           string `json:"status"`
	TotalTime        uint64 `json:"total-time"`
	ExpectedDowntime uint64 `json:"expected-downtime"`
	RAM              struct {
		Total          uint64  `json:"total"`
		Remaining      uint64  `json:"remaining"`
		Transferred    uint64  `json:"transferred"`
		DirtyPagesRate uint64  `json:"dirty-pages-rate"`
		Mbps           float64 `json:"mbps"`
	} `json:"ram"`
}

// qmpState maps a QEMU RunState to hyperview's state and reason.
func qmpState(s string) (state, reason string) {
	switch s {
	case "running":
		return "running", ""
	case "guest-panicked":
		return "crashed", s
	case "shutdown":
		return "shutdown", ""
	case "suspended":
		return "pmsuspended", ""
	case "paused":
		return "paused", "user"
	}
	return "paused", s // io-error, internal-error, watchdog, inmigrate, ...
}

// qmpSocket finds a server-mode QMP unix socket on a QEMU command line,
// either "-qmp unix:PATH,server..." or a "-chardev socket,...,server" bound
// to "-mon chardev=ID,mode=control".
func qmpSocket(args []string) string {
	chardevs := make(map[string]string)
	var monitors []string
	for i := 0; i+1 < len(args); i++ {
		opt, val := strings.TrimPrefix(args[i], "-"), args[i+1]
		switch opt {
		case "-qmp", "qmp", "-qmp-pretty", "qmp-pretty":
			if path, ok := strings.CutPrefix(val, "unix:"); ok {
				path, flags, _ := strings.Cut(path, ",")
				if strings.Contains(","+flags, ",server") {
					return path
				}
			}
		case "chardev", "-chardev":
			if !strings.HasPrefix(val, "socket,") {
				continue
			}
			server := false
			for _, kv := range strings.Split(val, ",") {
				if kv == "server" || kv == "server=on" {
					server = true
				}
			}
			if id, path := qemuOpt(val, "id"), qemuOpt(val, "path"); server && id != "" && path != "" {
				chardevs[id] = path
			}
		case "mon", "-mon":
			if qemuOpt(val, "mode") == "control" {
				monitors = append(monitors, qemuOpt(val, "chardev"))
			}
		}
	}
	for _, id := range monitors {
		if p, ok := chardevs[id]; ok {
			return p
		}
	}
	return ""
}
