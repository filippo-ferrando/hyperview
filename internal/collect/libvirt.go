package collect

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"hyperview/internal/store"

	"github.com/digitalocean/go-libvirt"
)

// DefaultLibvirtSockets are tried in order when no socket is configured:
// the monolithic daemon, the modular virtqemud daemon, then their
// read-only variants usable without root.
var DefaultLibvirtSockets = []string{
	"/run/libvirt/libvirt-sock",
	"/run/libvirt/virtqemud-sock",
	"/run/libvirt/libvirt-sock-ro",
	"/run/libvirt/virtqemud-sock-ro",
}

// xmlRefresh bounds how stale the cached domain XML may get; device
// hotplug is picked up within this window.
const xmlRefresh = 30 * time.Second

type domainXML struct {
	Devices struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Source struct {
				File string `xml:"file,attr"`
				Dev  string `xml:"dev,attr"`
				Name string `xml:"name,attr"`
			} `xml:"source"`
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
		} `xml:"disk"`
		Interfaces []struct {
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
		} `xml:"interface"`
	} `xml:"devices"`
}

type cachedXML struct {
	domID   int32
	fetched time.Time
	disks   []DiskSource
	ifaces  []string
}

// DiskSource maps a guest disk to its host backing path.
type DiskSource struct {
	Target string
	Path   string // file or block device; empty for network disks
}

type LibvirtCollector struct {
	mu      sync.Mutex
	sockets []string
	conn    net.Conn
	l       *libvirt.Libvirt
	sock    string

	rates       *rateTracker
	xmlCache    map[string]*cachedXML
	statsPeriod map[string]int32 // uuid -> domain ID the period was set for
	alive       []store.DomainID
	pids        map[store.DomainID]int
}

func NewLibvirtCollector(sockets ...string) *LibvirtCollector {
	if len(sockets) == 0 {
		sockets = DefaultLibvirtSockets
	}
	return &LibvirtCollector{
		sockets:     sockets,
		rates:       newRateTracker(),
		xmlCache:    make(map[string]*cachedXML),
		statsPeriod: make(map[string]int32),
		pids:        make(map[store.DomainID]int),
	}
}

func (lc *LibvirtCollector) Name() string { return "libvirt" }

func (lc *LibvirtCollector) Alive() []store.DomainID { return lc.alive }

// PIDs returns the hypervisor PID of each running libvirt domain, used by
// other discoverers to skip processes libvirt already owns.
func (lc *LibvirtCollector) PIDs() map[int]bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	out := make(map[int]bool, len(lc.pids))
	for _, pid := range lc.pids {
		out[pid] = true
	}
	return out
}

// Connected reports the socket in use, or "" when libvirt is unreachable.
func (lc *LibvirtCollector) Connected() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.l == nil {
		return ""
	}
	return lc.sock
}

func (lc *LibvirtCollector) connect() error {
	if lc.l != nil && lc.l.IsConnected() {
		return nil
	}
	lc.disconnect()

	var errs []error
	for _, sock := range lc.sockets {
		if _, err := os.Stat(sock); err != nil {
			continue
		}
		conn, err := net.DialTimeout("unix", sock, 2*time.Second)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sock, err))
			continue
		}
		l := libvirt.New(conn)
		if err := l.Connect(); err != nil {
			conn.Close()
			errs = append(errs, fmt.Errorf("%s: %w", sock, err))
			continue
		}
		lc.conn, lc.l, lc.sock = conn, l, sock
		return nil
	}
	if len(errs) == 0 {
		return errors.New("no libvirt socket found")
	}
	return errors.Join(errs...)
}

func (lc *LibvirtCollector) disconnect() {
	if lc.l != nil {
		_ = lc.l.Disconnect()
	}
	if lc.conn != nil {
		_ = lc.conn.Close()
	}
	lc.l, lc.conn, lc.sock = nil, nil, ""
}

func (lc *LibvirtCollector) Close() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.disconnect()
	return nil
}

func (lc *LibvirtCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if err := lc.connect(); err != nil {
		lc.alive = nil
		lc.pids = map[store.DomainID]int{}
		return fmt.Errorf("libvirt unavailable: %w", err)
	}

	domains, _, err := lc.l.ConnectListAllDomains(1, 0)
	if err != nil {
		lc.disconnect()
		return err
	}

	now := time.Now()
	alive := make([]store.DomainID, 0, len(domains))
	pids := make(map[store.DomainID]int, len(domains))
	seenUUID := make(map[string]bool, len(domains))

	for _, d := range domains {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		uuid := formatUUID(d.UUID)
		seenUUID[uuid] = true

		state, reason, err := lc.l.DomainGetState(d, 0)
		if err != nil {
			continue
		}
		id := store.DomainID(uuid)
		alive = append(alive, id)

		snap := store.DomainSnapshot{
			ID:     id,
			Name:   d.Name,
			UUID:   uuid,
			Source: "libvirt",
			State:  domainStateName(state),
			Reason: domainStateReason(state, reason),
		}

		_, maxMem, _, nrVCPU, _, err := lc.l.DomainGetInfo(d)
		if err == nil {
			snap.Mem.MaxKiB = maxMem
		}

		if state == int32(libvirt.DomainRunning) || state == int32(libvirt.DomainPaused) {
			snap.PID = libvirtPID(d.Name)
			if snap.PID > 0 {
				pids[id] = snap.PID
			}
			lc.collectRunning(d, uuid, int32(nrVCPU), &snap, now)
		}

		s.Upsert(id, func(cur *store.DomainSnapshot) { mergeLibvirt(cur, &snap) })
	}

	for uuid := range lc.xmlCache {
		if !seenUUID[uuid] {
			delete(lc.xmlCache, uuid)
			delete(lc.statsPeriod, uuid)
		}
	}
	lc.rates.sweep()
	lc.alive = alive
	lc.pids = pids
	return nil
}

// mergeLibvirt overwrites the fields libvirt owns while keeping what other
// collectors (proc, eBPF) wrote into the snapshot.
func mergeLibvirt(cur, n *store.DomainSnapshot) {
	cur.Name, cur.UUID, cur.Source = n.Name, n.UUID, n.Source
	cur.PID, cur.State, cur.Reason = n.PID, n.State, n.Reason
	cur.Migration = n.Migration

	rss, minor, major := cur.Mem.RssKiB, cur.Mem.MinorFltRate, cur.Mem.MajorFltRate
	cur.Mem = n.Mem
	if rss > 0 {
		cur.Mem.RssKiB = rss
	}
	cur.Mem.MinorFltRate, cur.Mem.MajorFltRate = minor, major

	// vCPU slices are rebuilt by libvirt; carry over per-thread data.
	old := cur.VCPUs
	cur.VCPUs = n.VCPUs
	for i := range cur.VCPUs {
		if i < len(old) {
			v := &cur.VCPUs[i]
			idx, cpu, host := v.Index, v.CPUPercent, v.HostCPU
			*v = old[i]
			v.Index, v.CPUPercent, v.HostCPU = idx, cpu, host
		}
	}

	oldIf := make(map[string]store.IfaceStat, len(cur.Ifaces))
	for _, i := range cur.Ifaces {
		oldIf[i.Name] = i
	}
	cur.Ifaces = n.Ifaces
	for i := range cur.Ifaces {
		if o, ok := oldIf[cur.Ifaces[i].Name]; ok {
			cur.Ifaces[i].Ifindex = o.Ifindex
		}
	}
	cur.Disks = n.Disks
	if !n.Running() && n.State != "paused" {
		cur.KVM = store.KVMStat{}
	}
}

func (lc *LibvirtCollector) collectRunning(d libvirt.Domain, uuid string, nrVCPU int32, snap *store.DomainSnapshot, now time.Time) {
	if nrVCPU > 0 {
		if infos, _, err := lc.l.DomainGetVcpus(d, nrVCPU, 0); err == nil {
			snap.VCPUs = make([]store.VCPUStat, len(infos))
			for i, info := range infos {
				key := fmt.Sprintf("%s/vcpu%d", uuid, info.Number)
				snap.VCPUs[i] = store.VCPUStat{
					Index:      int(info.Number),
					HostCPU:    int(info.CPU),
					CPUPercent: lc.rates.rate(key, float64(info.CPUTime), now) / 1e7, // ns/s -> %
				}
			}
		}
	}

	if lc.statsPeriod[uuid] != d.ID {
		// Without a period the balloon driver never refreshes guest stats.
		_ = lc.l.DomainSetMemoryStatsPeriod(d, 2, libvirt.DomainMemLive)
		lc.statsPeriod[uuid] = d.ID
	}
	if stats, err := lc.l.DomainMemoryStats(d, uint32(libvirt.DomainMemoryStatNr), 0); err == nil {
		for _, ms := range stats {
			switch libvirt.DomainMemoryStatTags(ms.Tag) {
			case libvirt.DomainMemoryStatActualBalloon:
				snap.Mem.BalloonKiB = ms.Val
			case libvirt.DomainMemoryStatAvailable:
				snap.Mem.AvailableKiB = ms.Val
			case libvirt.DomainMemoryStatUsable:
				snap.Mem.UsableKiB = ms.Val
			case libvirt.DomainMemoryStatUnused:
				snap.Mem.UnusedKiB = ms.Val
			case libvirt.DomainMemoryStatRss:
				snap.Mem.RssKiB = ms.Val
			case libvirt.DomainMemoryStatSwapIn:
				snap.Mem.SwapInRate = lc.rates.rate(uuid+"/swapin", float64(ms.Val), now)
			case libvirt.DomainMemoryStatSwapOut:
				snap.Mem.SwapOutRate = lc.rates.rate(uuid+"/swapout", float64(ms.Val), now)
			case libvirt.DomainMemoryStatHugetlbPgfail:
				snap.Mem.HugetlbFail = ms.Val
			}
		}
	}

	x := lc.domainXML(d, uuid, now)
	if x != nil {
		for _, ifname := range x.ifaces {
			rxB, rxP, rxE, rxD, txB, txP, txE, txD, err := lc.l.DomainInterfaceStats(d, ifname)
			if err != nil {
				continue
			}
			k := uuid + "/net/" + ifname
			snap.Ifaces = append(snap.Ifaces, store.IfaceStat{
				Name:    ifname,
				RxBps:   lc.rates.rate(k+"/rxb", float64(rxB), now),
				TxBps:   lc.rates.rate(k+"/txb", float64(txB), now),
				RxPps:   lc.rates.rate(k+"/rxp", float64(rxP), now),
				TxPps:   lc.rates.rate(k+"/txp", float64(txP), now),
				RxErrs:  nonNeg(rxE),
				TxErrs:  nonNeg(txE),
				RxDrops: nonNeg(rxD),
				TxDrops: nonNeg(txD),
				DropRate: lc.rates.rate(k+"/drop", float64(nonNeg(rxD)+nonNeg(txD)), now),
			})
		}
		for _, disk := range x.disks {
			rdReq, rdB, wrReq, wrB, errs, err := lc.l.DomainBlockStats(d, disk.Target)
			if err != nil {
				continue
			}
			k := uuid + "/blk/" + disk.Target
			snap.Disks = append(snap.Disks, store.DiskStat{
				Dev:       disk.Target,
				RdBps:     lc.rates.rate(k+"/rdb", float64(rdB), now),
				WrBps:     lc.rates.rate(k+"/wrb", float64(wrB), now),
				RdIOPS:    lc.rates.rate(k+"/rdr", float64(rdReq), now),
				WrIOPS:    lc.rates.rate(k+"/wrr", float64(wrReq), now),
				ErrsTotal: errs,
			})
		}
	}

	snap.Migration = lc.jobStats(d)
}

func (lc *LibvirtCollector) domainXML(d libvirt.Domain, uuid string, now time.Time) *cachedXML {
	c := lc.xmlCache[uuid]
	if c != nil && c.domID == d.ID && now.Sub(c.fetched) < xmlRefresh {
		return c
	}
	desc, err := lc.l.DomainGetXMLDesc(d, 0)
	if err != nil {
		return c
	}
	var dx domainXML
	if err := xml.Unmarshal([]byte(desc), &dx); err != nil {
		return c
	}
	c = &cachedXML{domID: d.ID, fetched: now}
	for _, i := range dx.Devices.Interfaces {
		if i.Target.Dev != "" {
			c.ifaces = append(c.ifaces, i.Target.Dev)
		}
	}
	for _, k := range dx.Devices.Disks {
		if k.Target.Dev == "" || k.Device == "cdrom" || k.Device == "floppy" {
			continue
		}
		path := k.Source.File
		if path == "" {
			path = k.Source.Dev
		}
		c.disks = append(c.disks, DiskSource{Target: k.Target.Dev, Path: path})
	}
	lc.xmlCache[uuid] = c
	return c
}

// DiskSources returns the host backing paths of every disk of a domain.
func (lc *LibvirtCollector) DiskSources(id store.DomainID) []DiskSource {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if c := lc.xmlCache[id]; c != nil {
		return append([]DiskSource(nil), c.disks...)
	}
	return nil
}

func (lc *LibvirtCollector) jobStats(d libvirt.Domain) *store.MigrationStat {
	typ, params, err := lc.l.DomainGetJobStats(d, 0)
	if err != nil || typ == 0 { // VIR_DOMAIN_JOB_NONE
		return nil
	}
	p := make(map[string]uint64, len(params))
	for _, tp := range params {
		p[tp.Field] = typedParamUint(tp.Value)
	}
	op := jobOperation(p["operation"])
	if op != "migration-out" && op != "migration-in" {
		return nil
	}
	status := map[int32]string{1: "active", 2: "active", 3: "completed", 4: "failed", 5: "cancelled"}[typ]
	return &store.MigrationStat{
		Status:         status,
		Operation:      op,
		ElapsedMs:      p["time_elapsed"],
		MemTotal:       p["memory_total"],
		MemProcessed:   p["memory_processed"],
		MemRemaining:   p["memory_remaining"],
		DirtyPageRate:  p["memory_dirty_rate"],
		Bps:            p["memory_bps"],
		ExpectedDownMs: p["downtime"],
	}
}

func typedParamUint(v libvirt.TypedParamValue) uint64 {
	switch x := v.I.(type) {
	case int32:
		return uint64(max(x, 0))
	case uint32:
		return uint64(x)
	case int64:
		return uint64(max(x, 0))
	case uint64:
		return x
	case float64:
		return uint64(max(x, 0))
	}
	return 0
}

func jobOperation(op uint64) string {
	switch op {
	case 4:
		return "migration-in"
	case 5:
		return "migration-out"
	}
	return strconv.FormatUint(op, 10)
}

// libvirtPID reads the pidfile libvirt keeps for each running QEMU domain.
func libvirtPID(name string) int {
	for _, dir := range []string{"/run/libvirt/qemu", "/var/run/libvirt/qemu"} {
		b, err := os.ReadFile(filepath.Join(dir, name+".pid"))
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}

func formatUUID(u libvirt.UUID) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func nonNeg(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

func domainStateName(state int32) string {
	switch libvirt.DomainState(state) {
	case libvirt.DomainRunning:
		return "running"
	case libvirt.DomainBlocked:
		return "blocked"
	case libvirt.DomainPaused:
		return "paused"
	case libvirt.DomainShutdown:
		return "shutdown"
	case libvirt.DomainShutoff:
		return "shut off"
	case libvirt.DomainCrashed:
		return "crashed"
	case libvirt.DomainPmsuspended:
		return "pmsuspended"
	}
	return "unknown"
}

// domainStateReason decodes the virDomain*Reason enums worth surfacing.
func domainStateReason(state, reason int32) string {
	var names []string
	switch libvirt.DomainState(state) {
	case libvirt.DomainRunning:
		names = []string{"", "booted", "migrated", "restored", "from snapshot", "unpaused",
			"migration cancelled", "save cancelled", "wakeup", "crashed", "postcopy", "postcopy failed"}
	case libvirt.DomainPaused:
		names = []string{"", "user", "migration", "save", "dump", "ioerror", "watchdog",
			"from snapshot", "shutting down", "snapshot", "crashed", "starting up",
			"postcopy", "postcopy failed", "api error"}
	case libvirt.DomainShutoff:
		names = []string{"", "shutdown", "destroyed", "crashed", "migrated", "saved",
			"failed", "from snapshot", "daemon"}
	case libvirt.DomainCrashed:
		names = []string{"", "panicked"}
	}
	if reason >= 0 && int(reason) < len(names) {
		return names[reason]
	}
	return ""
}
