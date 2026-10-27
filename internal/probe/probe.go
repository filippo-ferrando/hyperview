// Package probe loads hyperview's eBPF programs and exposes their data.
//
// Every program is loaded and attached on its own, so a tracepoint missing
// on the running kernel (or a verifier rejection) only disables that one
// probe. Status reports what is active and why the rest is not.
package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"hyperview/internal/bpf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Features that can be disabled through Config.
const (
	FeatKVMExits  = "kvm-exits"
	FeatKVMErrors = "kvm-errors"
	FeatKVMIRQ    = "kvm-irq"
	FeatKVMHalt   = "kvm-halt"
	FeatRunqueue  = "runqueue"
	FeatLifecycle = "lifecycle"
	FeatBlock     = "block"
	FeatNetDrops  = "net-drops"
	FeatOOM       = "oom"
	FeatMCE       = "mce"
)

// AllFeatures lists every feature in display order.
var AllFeatures = []string{FeatKVMExits, FeatKVMErrors, FeatKVMIRQ, FeatKVMHalt, FeatRunqueue,
	FeatLifecycle, FeatBlock, FeatNetDrops, FeatOOM, FeatMCE}

type State int

const (
	Attached    State = iota
	Unavailable       // the kernel lacks the hook (module not loaded, other arch, old kernel)
	Failed            // the hook exists but loading or attaching failed
	Disabled          // turned off by configuration
)

func (s State) String() string {
	return [...]string{"attached", "unavailable", "failed", "disabled"}[s]
}

type Status struct {
	Feature string
	Probe   string // e.g. "kvm:kvm_exit"
	State   State
	Err     string
}

type Config struct {
	Disabled map[string]bool
}

type fieldVar struct {
	field    string
	alt      string // alternative field name on other architectures
	variable string
	size     uint32
	optional bool
}

type probeDef struct {
	feature  string
	prog     string
	group    string
	event    string
	btf      bool // tp_btf program; classic tracepoint otherwise
	fields   []fieldVar
	fallback string // program to try when prog cannot load (older kernels)
}

var probeDefs = []probeDef{
	{feature: FeatKVMExits, prog: bpf.HyperviewProgKvmExit, group: "kvm", event: "kvm_exit", fields: []fieldVar{
		{field: "exit_reason", alt: "esr_ec", variable: bpf.HyperviewVarOffKvmExitReason, size: 4},
		{field: "ret", variable: bpf.HyperviewVarOffKvmExitReason2, size: 4, optional: true},
	}},
	{feature: FeatKVMErrors, prog: bpf.HyperviewProgKvmUserspaceExit, group: "kvm", event: "kvm_userspace_exit", fields: []fieldVar{
		{field: "reason", variable: bpf.HyperviewVarOffUexitReason, size: 4},
		{field: "errno", variable: bpf.HyperviewVarOffUexitErrno, size: 4},
	}},
	{feature: FeatKVMErrors, prog: bpf.HyperviewProgKvmEmulateInsn, group: "kvm", event: "kvm_emulate_insn", fields: []fieldVar{
		{field: "failed", variable: bpf.HyperviewVarOffEmulFailed, size: 1},
		{field: "rip", variable: bpf.HyperviewVarOffEmulRip, size: 8},
	}},
	{feature: FeatKVMErrors, prog: bpf.HyperviewProgKvmInjException, group: "kvm", event: "kvm_inj_exception", fields: []fieldVar{
		{field: "exception", variable: bpf.HyperviewVarOffExcVector, size: 1},
		{field: "error_code", variable: bpf.HyperviewVarOffExcErrcode, size: 4},
	}},
	{feature: FeatKVMIRQ, prog: bpf.HyperviewProgKvmInjVirq, group: "kvm", event: "kvm_inj_virq"},
	{feature: FeatKVMHalt, prog: bpf.HyperviewProgKvmVcpuWakeup, group: "kvm", event: "kvm_vcpu_wakeup", fields: []fieldVar{
		{field: "ns", variable: bpf.HyperviewVarOffWakeNs, size: 8},
		{field: "waited", variable: bpf.HyperviewVarOffWakeWaited, size: 1},
	}},
	{feature: FeatRunqueue, prog: bpf.HyperviewProgSchedWakeup, group: "sched", event: "sched_wakeup", btf: true},
	{feature: FeatRunqueue, prog: bpf.HyperviewProgSchedWakeupNew, group: "sched", event: "sched_wakeup_new", btf: true},
	{feature: FeatRunqueue, prog: bpf.HyperviewProgSchedSwitch, group: "sched", event: "sched_switch", btf: true},
	{feature: FeatLifecycle, prog: bpf.HyperviewProgSchedProcessExit, group: "sched", event: "sched_process_exit", btf: true},
	{feature: FeatLifecycle, prog: bpf.HyperviewProgSignalGenerate, group: "signal", event: "signal_generate", btf: true},
	{feature: FeatBlock, prog: bpf.HyperviewProgBlockRqIssue, group: "block", event: "block_rq_issue", fields: []fieldVar{
		{field: "dev", variable: bpf.HyperviewVarOffRqiDev, size: 4},
		{field: "sector", variable: bpf.HyperviewVarOffRqiSector, size: 8},
		{field: "nr_sector", variable: bpf.HyperviewVarOffRqiNr, size: 4},
	}},
	{feature: FeatBlock, prog: bpf.HyperviewProgBlockRqComplete, group: "block", event: "block_rq_complete", fields: []fieldVar{
		{field: "dev", variable: bpf.HyperviewVarOffRqcDev, size: 4},
		{field: "sector", variable: bpf.HyperviewVarOffRqcSector, size: 8},
		{field: "nr_sector", variable: bpf.HyperviewVarOffRqcNr, size: 4},
		{field: "error", variable: bpf.HyperviewVarOffRqcError, size: 4},
	}},
	{feature: FeatNetDrops, prog: bpf.HyperviewProgKfreeSkbReason, group: "skb", event: "kfree_skb", btf: true, fallback: bpf.HyperviewProgKfreeSkb},
	{feature: FeatOOM, prog: bpf.HyperviewProgOomMarkVictim, group: "oom", event: "mark_victim", fields: []fieldVar{
		{field: "pid", variable: bpf.HyperviewVarOffOomPid, size: 4},
	}},
	{feature: FeatMCE, prog: bpf.HyperviewProgMceRecord, group: "mce", event: "mce_record", fields: []fieldVar{
		{field: "status", variable: bpf.HyperviewVarOffMceStatus, size: 8},
		{field: "addr", variable: bpf.HyperviewVarOffMceAddr, size: 8},
		{field: "bank", variable: bpf.HyperviewVarOffMceBank, size: 1},
		{field: "mcgstatus", variable: bpf.HyperviewVarOffMceMcgstatus, size: 8},
	}},
}

// Probes owns the loaded programs, their links and shared maps.
type Probes struct {
	mu      sync.Mutex
	status  []Status
	coll    *ebpf.Collection
	progs   []*ebpf.Program
	links   []link.Link
	reader  *ringbuf.Reader
	events  chan Event
	targets map[uint32]bool
	ifaces  map[uint32]uint32

	Arch      ExitArch
	DropNames DropReasons
}

// ErrPermission is returned when the process lacks the privileges to load
// eBPF programs (root, or CAP_BPF + CAP_PERFMON).
var ErrPermission = errors.New("eBPF requires root (or CAP_BPF and CAP_PERFMON)")

// Load loads and attaches every enabled probe. It fails only when nothing
// can be loaded at all; per-probe problems are reported by Status.
func Load(cfg Config) (*Probes, error) {
	// Kernels before 5.11 account BPF memory against RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, ErrPermission
		}
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	spec, err := bpf.LoadHyperview()
	if err != nil {
		return nil, fmt.Errorf("parse embedded BPF object: %w", err)
	}

	p := &Probes{
		events:  make(chan Event, 1024),
		targets: make(map[uint32]bool),
		ifaces:  make(map[uint32]uint32),
		Arch:    HostExitArch(),
	}

	// Resolve tracepoint layouts first: variables are shared by all programs.
	var plan []probeDef
	for _, def := range probeDefs {
		st := Status{Feature: def.feature, Probe: def.group + ":" + def.event}
		switch {
		case cfg.Disabled[def.feature]:
			st.State = Disabled
		case !def.btf:
			if err := resolveFields(spec, def); err != nil {
				st.State, st.Err = Unavailable, err.Error()
			} else {
				plan = append(plan, def)
				continue
			}
		default:
			plan = append(plan, def)
			continue
		}
		p.status = append(p.status, st)
	}

	mapsSpec := spec.Copy()
	mapsSpec.Programs = map[string]*ebpf.ProgramSpec{}
	coll, err := ebpf.NewCollection(mapsSpec)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, ErrPermission
		}
		return nil, fmt.Errorf("create BPF maps: %w", err)
	}
	p.coll = coll

	cache := btf.NewCache()
	for _, def := range plan {
		st := Status{Feature: def.feature, Probe: def.group + ":" + def.event}
		prog, err := p.loadProgram(spec, def.prog, cache)
		if err != nil && def.fallback != "" {
			slog.Debug("probe falling back", slog.String("prog", def.prog), slog.Any("err", err))
			prog, err = p.loadProgram(spec, def.fallback, cache)
		}
		if err == nil {
			var l link.Link
			if def.btf {
				l, err = link.AttachTracing(link.TracingOptions{Program: prog})
			} else {
				l, err = link.Tracepoint(def.group, def.event, prog, nil)
			}
			if err == nil {
				p.progs = append(p.progs, prog)
				p.links = append(p.links, l)
				p.status = append(p.status, st)
				continue
			}
			prog.Close()
		}
		st.State, st.Err = classify(err)
		slog.Warn("eBPF probe not attached", slog.String("probe", st.Probe), slog.Any("err", err))
		p.status = append(p.status, st)
	}

	if len(p.links) == 0 {
		p.Close()
		return nil, errors.New("no eBPF probe could be attached")
	}

	if slices.ContainsFunc(p.status, func(s Status) bool { return s.Feature == FeatNetDrops && s.State == Attached }) {
		p.DropNames = loadDropReasons()
	}

	p.reader, err = ringbuf.NewReader(coll.Maps[bpf.HyperviewMapEvents])
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("open event ring buffer: %w", err)
	}
	go p.readEvents()

	slices.SortStableFunc(p.status, func(a, b Status) int {
		return slices.Index(AllFeatures, a.Feature) - slices.Index(AllFeatures, b.Feature)
	})
	return p, nil
}

func resolveFields(spec *ebpf.CollectionSpec, def probeDef) error {
	fields, err := tracepointFormat(def.group, def.event)
	if err != nil {
		return err
	}
	for _, fv := range def.fields {
		f, ok := fields[fv.field]
		if !ok && fv.alt != "" {
			f, ok = fields[fv.alt]
		}
		if !ok {
			if fv.optional {
				continue
			}
			return fmt.Errorf("field %q missing from %s:%s", fv.field, def.group, def.event)
		}
		if f.Size != fv.size {
			return fmt.Errorf("field %q of %s:%s has size %d, expected %d", f.Name, def.group, def.event, f.Size, fv.size)
		}
		v, ok := spec.Variables[fv.variable]
		if !ok {
			return fmt.Errorf("BPF object lacks variable %s", fv.variable)
		}
		if err := v.Set(f.Offset); err != nil {
			return fmt.Errorf("set %s: %w", fv.variable, err)
		}
	}
	return nil
}

// loadProgram loads one program against the shared maps.
func (p *Probes) loadProgram(spec *ebpf.CollectionSpec, name string, cache *btf.Cache) (*ebpf.Program, error) {
	one := spec.Copy()
	ps, ok := one.Programs[name]
	if !ok {
		return nil, fmt.Errorf("program %s not in BPF object", name)
	}
	one.Programs = map[string]*ebpf.ProgramSpec{name: ps}
	coll, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{
		MapReplacements: p.coll.Maps,
		Cache:           cache,
	})
	if err != nil {
		return nil, err
	}
	defer coll.Close()
	return coll.DetachProgram(name), nil
}

func classify(err error) (State, string) {
	msg := err.Error()
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		// The last verifier lines carry the actual reason.
		lines := ve.Log
		if len(lines) > 3 {
			lines = lines[len(lines)-3:]
		}
		msg = "verifier: " + strings.Join(lines, " | ")
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, btf.ErrNotFound) || errors.Is(err, ebpf.ErrNotSupported) {
		return Unavailable, msg
	}
	return Failed, msg
}

func (p *Probes) Status() []Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.status)
}

// FeatureActive reports whether at least one probe of feature is attached.
func (p *Probes) FeatureActive(feature string) bool {
	for _, s := range p.Status() {
		if s.Feature == feature && s.State == Attached {
			return true
		}
	}
	return false
}

func (p *Probes) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, l := range p.links {
		_ = l.Close()
	}
	for _, prog := range p.progs {
		_ = prog.Close()
	}
	p.links, p.progs = nil, nil
	if p.reader != nil {
		_ = p.reader.Close()
	}
	if p.coll != nil {
		p.coll.Close()
		p.coll = nil
	}
}

func (p *Probes) m(name string) *ebpf.Map { return p.coll.Maps[name] }

// SetTargets replaces the set of monitored hypervisor processes and drops
// all per-process state of the ones that went away.
func (p *Probes) SetTargets(tgids map[uint32]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	one := uint32(1)
	for tgid := range tgids {
		if !p.targets[tgid] {
			_ = p.m(bpf.HyperviewMapTargets).Update(tgid, one, ebpf.UpdateAny)
		}
	}
	var gone []uint32
	for tgid := range p.targets {
		if !tgids[tgid] {
			_ = p.m(bpf.HyperviewMapTargets).Delete(tgid)
			gone = append(gone, tgid)
		}
	}
	p.targets = maps.Clone(tgids)
	if len(gone) == 0 {
		return
	}
	isGone := func(t uint32) bool { return slices.Contains(gone, t) }
	deleteKeys(p.m(bpf.HyperviewMapVmExits), func(k bpf.HyperviewExitKey) bool { return isGone(k.Tgid) })
	deleteKeys(p.m(bpf.HyperviewMapVmUexits), func(k bpf.HyperviewExitKey) bool { return isGone(k.Tgid) })
	for _, t := range gone {
		_ = p.m(bpf.HyperviewMapVmStats).Delete(t)
		_ = p.m(bpf.HyperviewMapBlkVmHist).Delete(t)
	}
}

// SetIfaces replaces the set of tap interfaces (ifindex -> tgid) whose
// packet drops are counted.
func (p *Probes) SetIfaces(ifaces map[uint32]uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for idx, tgid := range ifaces {
		if old, ok := p.ifaces[idx]; !ok || old != tgid {
			_ = p.m(bpf.HyperviewMapTargetIfaces).Update(idx, tgid, ebpf.UpdateAny)
		}
	}
	var gone []uint32
	for idx := range p.ifaces {
		if _, ok := ifaces[idx]; !ok {
			_ = p.m(bpf.HyperviewMapTargetIfaces).Delete(idx)
			gone = append(gone, idx)
		}
	}
	p.ifaces = maps.Clone(ifaces)
	if len(gone) > 0 {
		deleteKeys(p.m(bpf.HyperviewMapSkbDrops), func(k bpf.HyperviewDropKey) bool { return slices.Contains(gone, k.Ifindex) })
	}
}

func deleteKeys[K any](m *ebpf.Map, match func(K) bool) {
	var (
		k    K
		keys []K
	)
	it := m.Iterate()
	for it.Next(&k, nil) {
		if match(k) {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		_ = m.Delete(k)
	}
}

// ExitCounts returns cumulative kvm_exit counts: tgid -> raw reason -> n.
func (p *Probes) ExitCounts() map[uint32]map[uint32]uint64 {
	return p.perCPUExitMap(bpf.HyperviewMapVmExits)
}

// UserExitCounts returns cumulative KVM_RUN returns: tgid -> KVM_EXIT_* -> n.
func (p *Probes) UserExitCounts() map[uint32]map[uint32]uint64 {
	return p.perCPUExitMap(bpf.HyperviewMapVmUexits)
}

func (p *Probes) perCPUExitMap(name string) map[uint32]map[uint32]uint64 {
	out := make(map[uint32]map[uint32]uint64)
	var (
		k    bpf.HyperviewExitKey
		vals []uint64
	)
	it := p.m(name).Iterate()
	for it.Next(&k, &vals) {
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		if out[k.Tgid] == nil {
			out[k.Tgid] = make(map[uint32]uint64)
		}
		out[k.Tgid][k.Reason] += sum
	}
	return out
}

type VMCounters = bpf.HyperviewVmCounters

// VMCounters returns cumulative per-VM counters summed over all CPUs.
func (p *Probes) VMCounters() map[uint32]VMCounters {
	out := make(map[uint32]VMCounters)
	var (
		tgid uint32
		vals []bpf.HyperviewVmCounters
	)
	it := p.m(bpf.HyperviewMapVmStats).Iterate()
	for it.Next(&tgid, &vals) {
		var s VMCounters
		for _, v := range vals {
			s.IrqInjections += v.IrqInjections
			s.Exceptions += v.Exceptions
			s.EmulFailures += v.EmulFailures
			s.HaltPollsOk += v.HaltPollsOk
			s.HaltWaits += v.HaltWaits
			s.HaltWaitNs += v.HaltWaitNs
		}
		out[tgid] = s
	}
	return out
}

type VCPUCounters = bpf.HyperviewVcpuCounters

// VCPUCounters returns cumulative per-thread counters keyed by tid.
func (p *Probes) VCPUCounters() map[uint32]VCPUCounters {
	return readMap[uint32, VCPUCounters](p.m(bpf.HyperviewMapVcpuStats))
}

// RunqHists returns cumulative run-queue latency histograms keyed by tid.
func (p *Probes) RunqHists() map[uint32]Hist { return p.hists(bpf.HyperviewMapRunqHist) }

// BlockDevHists returns cumulative request latency per kernel dev_t.
func (p *Probes) BlockDevHists() map[uint32]Hist { return p.hists(bpf.HyperviewMapBlkDevHist) }

// BlockVMHists returns cumulative request latency of requests issued by
// each monitored hypervisor process.
func (p *Probes) BlockVMHists() map[uint32]Hist { return p.hists(bpf.HyperviewMapBlkVmHist) }

// BlockErrors returns cumulative failed requests per kernel dev_t.
func (p *Probes) BlockErrors() map[uint32]uint64 {
	return readMap[uint32, uint64](p.m(bpf.HyperviewMapBlkErrors))
}

type DropKey = bpf.HyperviewDropKey

// Drops returns cumulative packet drops per (ifindex, reason).
func (p *Probes) Drops() map[DropKey]uint64 {
	return readMap[DropKey, uint64](p.m(bpf.HyperviewMapSkbDrops))
}

func (p *Probes) hists(name string) map[uint32]Hist {
	raw := readMap[uint32, bpf.HyperviewHist](p.m(name))
	out := make(map[uint32]Hist, len(raw))
	for k, h := range raw {
		out[k] = histFromBPF(&h)
	}
	return out
}

func readMap[K comparable, V any](m *ebpf.Map) map[K]V {
	out := make(map[K]V)
	var (
		k K
		v V
	)
	it := m.Iterate()
	for it.Next(&k, &v) {
		out[k] = v
	}
	return out
}

// EventType mirrors enum event_type in the BPF program.
type EventType uint32

const (
	EvKVMUserExit EventType = iota + 1
	EvKVMEmulFail
	EvKVMException
	EvOOMVictim
	EvSignal
	EvExit
	EvBlockError
	EvMCE
)

// Event is a discrete kernel event delivered through the ring buffer.
type Event struct {
	Time       time.Time
	Type       EventType
	TGID       uint32
	TID        uint32
	CPU        uint32
	A, B, C, D int64
	Comm       string
}

// Events delivers kernel events until Close.
func (p *Probes) Events() <-chan Event { return p.events }

func (p *Probes) readEvents() {
	defer close(p.events)
	for {
		rec, err := p.reader.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				slog.Error("eBPF event reader stopped", slog.Any("err", err))
			}
			return
		}
		var raw bpf.HyperviewEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		ev := Event{
			Time: monoToWall(raw.Ts),
			Type: EventType(raw.Type),
			TGID: raw.Tgid, TID: raw.Tid, CPU: raw.Cpu,
			A: raw.A, B: raw.B, C: raw.C, D: raw.D,
			Comm: cString(raw.Comm[:]),
		}
		select {
		case p.events <- ev:
		default: // consumer is behind; drop rather than stall the ring
		}
	}
}

func monoToWall(ns uint64) time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(uint64(ts.Nano()) - ns))
}

func cString(b []int8) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}
