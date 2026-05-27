# hyperview — project blueprint

> A Go-native, htop-style TUI for monitoring KVM/libvirt virtual machines in real time.  
> Target platforms: RHEL-compatible (8.6+, 9.x) · Ubuntu 20.04+ / Debian derivatives.

---

## Table of contents

1. [Goals & non-goals](#1-goals--non-goals)
2. [Technology stack](#2-technology-stack)
3. [Repository layout](#3-repository-layout)
4. [Data model](#4-data-model)
5. [Collector subsystems](#5-collector-subsystems)
6. [eBPF subsystem detail](#6-ebpf-subsystem-detail)
7. [TUI architecture](#7-tui-architecture)
8. [Cross-distro compatibility matrix](#8-cross-distro-compatibility-matrix)
9. [Development timeline](#9-development-timeline)
10. [Build & packaging](#10-build--packaging)
11. [Testing strategy](#11-testing-strategy)
12. [Open questions / future work](#12-open-questions--future-work)

---

## 1. Goals & non-goals

### Goals

- Real-time per-domain stats (CPU, memory, net, I/O, KVM events, migration) refreshed at ≤ 250 ms.
- Single statically-linked binary — zero runtime deps beyond a running libvirt socket.
- eBPF when available; silent fallback to `/proc` + libvirt APIs when not.
- Works on RHEL 8.6+, RHEL 9.x, Ubuntu 20.04+, Ubuntu 22.04+.
- Keyboard-driven TUI with sortable domain list and drill-down panels.

### Non-goals

- Guest-agent stats (requires qemu-guest-agent installed in every VM).
- Persistent storage / time-series database.
- Multi-host / remote hypervisor support (v1).
- Windows or macOS host support.

---

## 2. Technology stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | **Go 1.22+** | Single binary, strong concurrency, good eBPF ecosystem |
| TUI framework | **bubbletea** (`charmbracelet/bubbletea`) | MVU model, composable, testable without a terminal |
| TUI styling | **lipgloss** (`charmbracelet/lipgloss`) | Declarative, 256-color + truecolor |
| TUI tables | **bubbles/table** (`charmbracelet/bubbles`) | Sortable, scrollable, ships with bubbletea |
| libvirt RPC | **go-libvirt** (`digitalocean/go-libvirt`) | Pure Go, no CGo, connects over Unix socket |
| eBPF loader | **cilium/ebpf** + **bpf2go** | CO-RE relocation at load time, embed BPF ELF in binary |
| BPF programs | **C** (compiled with `clang -target bpf`) | Only dev-time dep; output embedded via `go:embed` |
| `/proc` parsing | **prometheus/procfs** | Battle-tested, handles `stat`, `smaps`, `net/dev` |
| QMP (QEMU monitor) | **stdlib net + encoding/json** | QMP protocol is simple enough; avoids extra deps |
| Logging | **log/slog** (stdlib, Go 1.21+) | Structured, zero-dep, writes to file not stdout |
| Testing | **testing** + **testify** | Standard + assertions; no integration test framework needed |
| Build tooling | **Makefile** + `go generate` | Orchestrates clang, bpf2go, cross-compilation |
| Packaging | **nFPM** | Generates `.rpm` and `.deb` from a single `nfpm.yaml` |

---

## 3. Repository layout

```
hyperview/
│
├── cmd/
│   └── hyperview/
│       └── main.go                  # flag parsing, wiring, signal handling
│
├── internal/
│   ├── collect/
│   │   ├── collector.go             # Collector interface + registry
│   │   ├── libvirt.go               # LibvirtCollector
│   │   ├── proc.go                  # ProcCollector
│   │   ├── ebpf.go                  # eBPFCollector  (//go:build linux)
│   │   ├── ebpf_stub.go             # no-op stub     (!linux)
│   │   └── qmp.go                   # QMPCollector
│   │
│   ├── bpf/
│   │   ├── kvm_events.c             # BPF C source: tracepoints + kprobes
│   │   ├── vmlinux.h                # generated: bpftool btf dump format c
│   │   └── kvm_events_bpfel.go      # generated: bpf2go output (little-endian)
│   │
│   ├── store/
│   │   ├── domain.go                # DomainStore, DomainSnapshot
│   │   └── ring.go                  # RingBuffer[T any]
│   │
│   ├── tui/
│   │   ├── model.go                 # root bubbletea Model
│   │   ├── keys.go                  # keybinding definitions
│   │   ├── styles.go                # lipgloss style tokens
│   │   └── panels/
│   │       ├── domains.go           # sortable domain list (main view)
│   │       ├── cpu.go               # per-vCPU bar chart
│   │       ├── mem.go               # memory + page fault detail
│   │       ├── net.go               # per-interface rx/tx sparklines
│   │       ├── io.go                # per-disk rd/wr sparklines
│   │       ├── kvm.go               # KVM exit reason histogram
│   │       └── migration.go         # live migration progress
│   │
│   └── version/
│       └── version.go               # ldflags-injected version string
│
├── go.mod
├── go.sum
├── Makefile
├── nfpm.yaml                        # RPM + DEB packaging spec
└── README.md
```

---

## 4. Data model

### 4.1 Core types (`internal/store/domain.go`)

```go
// DomainID is the libvirt UUID string.
type DomainID = string

// DomainSnapshot is an immutable point-in-time snapshot of all metrics
// for one domain. Collectors write these; the TUI reads them.
type DomainSnapshot struct {
    ID        DomainID
    Name      string
    State     string            // running | paused | shut off | ...

    // CPU
    VCPUs     []VCPUStat        // one entry per vCPU

    // Memory
    Mem       MemStat

    // Network  (one entry per virtual NIC)
    Ifaces    []IfaceStat

    // Block I/O (one entry per virtual disk)
    Disks     []DiskStat

    // KVM events (from eBPF or zeroed-out if unavailable)
    KVMEvents KVMEventStat

    // Migration (non-zero only during live migration)
    Migration *MigrationStat

    CollectedAt time.Time
}

type VCPUStat struct {
    Index      int
    CPUPercent float64   // delta(cpu_time) / wall_time * 100
    RunCount   uint64    // kvm_exit count (eBPF)
    WaitNs     uint64    // time blocked in host kernel (eBPF)
}

type MemStat struct {
    AllocKiB      uint64  // balloon: actual
    AvailableKiB  uint64  // balloon: available (inside guest)
    RssKiB        uint64  // host-side RSS of QEMU process
    MinorFaults   uint64  // delta from /proc/<pid>/stat
    MajorFaults   uint64  // delta from /proc/<pid>/stat
}

type IfaceStat struct {
    Name    string
    RxBytes uint64   // delta
    TxBytes uint64   // delta
    RxPkts  uint64
    TxPkts  uint64
}

type DiskStat struct {
    Dev     string
    RdBytes uint64   // delta
    WrBytes uint64   // delta
    RdReqs  uint64
    WrReqs  uint64
}

type KVMEventStat struct {
    Available     bool
    ExitReasons   map[uint32]uint64   // exit_reason -> count delta
    IRQInjections uint64
    HaltPollNs    uint64              // cumulative halt-poll time
    MMIOExits     uint64
}

type MigrationStat struct {
    Status          string    // "active" | "completed" | "failed"
    TotalPages      uint64
    DirtyPages      uint64
    DirtyPageRate   uint64    // pages/s
    MbpsDown        float64
    ExpectedDownMs  uint64
    TotalTimeMs     uint64
}
```

### 4.2 Ring buffer (`internal/store/ring.go`)

```go
// RingBuffer holds the last N snapshots for sparkline rendering.
// Generic, thread-unsafe (callers hold DomainStore's lock).
type RingBuffer[T any] struct {
    buf  []T
    pos  int
    size int
}

func NewRingBuffer[T any](size int) *RingBuffer[T]
func (r *RingBuffer[T]) Push(v T)
func (r *RingBuffer[T]) Slice() []T   // oldest → newest
```

### 4.3 DomainStore (`internal/store/domain.go`)

```go
type DomainStore struct {
    mu      sync.RWMutex
    domains map[DomainID]*domainEntry
}

type domainEntry struct {
    latest   DomainSnapshot
    cpuHist  *RingBuffer[float64]   // last 60 samples → sparkline
    rxHist   *RingBuffer[uint64]
    txHist   *RingBuffer[uint64]
}

func (s *DomainStore) Update(snap DomainSnapshot)
func (s *DomainStore) Snapshot() []DomainSnapshot     // sorted by name
func (s *DomainStore) Get(id DomainID) (DomainSnapshot, bool)
func (s *DomainStore) History(id DomainID) DomainHistory
```

---

## 5. Collector subsystems

### 5.1 Collector interface

```go
type Collector interface {
    // Name returns a short identifier used in logs and the status bar.
    Name() string

    // Collect is called every tick. It writes zero or more snapshots
    // into the store. It must return quickly (< tick interval).
    Collect(ctx context.Context, store *store.DomainStore) error

    // Close releases any held resources (sockets, maps, links).
    Close() error
}
```

### 5.2 LibvirtCollector

**Technology:** `digitalocean/go-libvirt` over `/var/run/libvirt/libvirt-sock`

**Metrics collected:**

| Metric | libvirt call | Notes |
|---|---|---|
| Domain list + state | `ConnectListAllDomains` | Runs every tick |
| vCPU time | `DomainGetVcpus` | Returns per-vCPU `cpu_time` ns; delta / wall_time = % |
| Memory stats | `DomainMemoryStats` | Requires balloon driver in guest |
| NIC stats | `DomainInterfaceStats` | Per-interface rx/tx bytes + packets |
| Disk stats | `DomainBlockStats` | Per-disk rd/wr bytes + requests |

**Connection strategy:** persistent Unix socket connection, reconnect with exponential backoff on `EPIPE`.

### 5.3 ProcCollector

**Technology:** `prometheus/procfs`, reads `/proc/<qemu_pid>/`

**QEMU PID discovery:** query libvirt for domain XML → extract `<emulator>` path → match against `/proc/*/cmdline` for `-name <domain-name>`. Cache PID, re-validate on ESRCH.

**Metrics collected:**

| Metric | Source | Notes |
|---|---|---|
| Minor page faults | `/proc/<pid>/stat` field 10 | Delta per interval |
| Major page faults | `/proc/<pid>/stat` field 12 | Delta per interval |
| vCPU thread CPU | `/proc/<pid>/task/*/stat` | One thread per vCPU; map via `DomainGetVcpuPinInfo` |
| Host RSS | `/proc/<pid>/status` VmRSS | Snapshot |
| Open FDs | `/proc/<pid>/fd` count | Optional, for debugging |

### 5.4 eBPFCollector

See [Section 6](#6-ebpf-subsystem-detail) for full detail.

**Technology:** `cilium/ebpf`, CO-RE BPF programs compiled with `clang -target bpf -O2 -g`

**Graceful degradation:**

```
startup probe:
  ├── /sys/kernel/btf/vmlinux exists?  → full CO-RE load
  ├── CAP_BPF or CAP_SYS_ADMIN?        → proceed
  ├── SELinux/seccomp blocking bpf()?   → log warning, disable eBPF
  └── kernel < 5.4?                     → log warning, disable eBPF
```

Status displayed in TUI header: `eBPF ✓` / `eBPF ✗ (fallback)`.

### 5.5 QMPCollector

**Technology:** stdlib `net.Dial("unix", ...)` + `encoding/json`

**Socket path:** `/var/run/libvirt/qemu/<domain-name>.monitor`

**Protocol flow:**

```
→ {"execute": "qmp_capabilities"}
← {"return": {}}
[poll loop]
→ {"execute": "query-migrate"}
← {"return": {"status": "active", "ram": {...}, "expected-downtime": 42, ...}}
→ {"execute": "query-status"}
← {"return": {"status": "running"}}
```

**Activation logic:** QMPCollector activates per-domain only when libvirt reports state `VIR_DOMAIN_PAUSED` or `VIR_DOMAIN_RUNNING` with a pending migration (detected by non-empty `query-migrate` status). Otherwise the goroutine sleeps.

---

## 6. eBPF subsystem detail

### 6.1 Tracepoints and kprobes used

| Probe | Type | Kernel version | Data extracted |
|---|---|---|---|
| `kvm:kvm_exit` | tracepoint | 4.7+ | `exit_reason`, `vcpu_id` |
| `kvm:kvm_entry` | tracepoint | 4.7+ | timestamp for entry latency |
| `kvm:kvm_inj_virq` | tracepoint | 4.7+ | IRQ number, type |
| `kvm:kvm_halt_poll_ns` | tracepoint | 5.4+ | `time`, `grow`/`shrink` |
| `kvm:kvm_mmu_page_fault` | tracepoint | 5.4+ | `gva`, `error_code` |
| `kvm:kvm_dirty_ring_push` | tracepoint | 5.11+ | dirty GFN count |
| `handle_mm_fault` | kprobe (fallback) | 4.x+ | minor/major fault for QEMU pid |

### 6.2 BPF maps

```c
// Per-CPU ring buffer for low-overhead event streaming
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kvm_events SEC(".maps");

// Per-vCPU exit reason histogram (exits since last drain)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 512);
    __type(key,   __u32);   // exit_reason
    __type(value, __u64);   // count
} exit_counts SEC(".maps");

// Target PID filter (updated by userspace when domains start/stop)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   __u32);   // tgid (QEMU pid)
    __type(value, __u8);    // 1 = monitored
} target_pids SEC(".maps");
```

### 6.3 BPF program skeleton (C)

```c
// internal/bpf/kvm_events.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ... map definitions above ...

struct kvm_exit_event {
    __u32 pid;
    __u32 vcpu_id;
    __u32 exit_reason;
    __u64 timestamp_ns;
};

SEC("tp/kvm/kvm_exit")
int handle_kvm_exit(struct trace_event_raw_kvm_exit *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&target_pids, &tgid))
        return 0;

    struct kvm_exit_event *e = bpf_ringbuf_reserve(&kvm_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid         = tgid;
    e->exit_reason = ctx->exit_reason;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);

    __u64 one = 1, *cnt;
    cnt = bpf_map_lookup_elem(&exit_counts, &ctx->exit_reason);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    else     bpf_map_update_elem(&exit_counts, &ctx->exit_reason, &one, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 6.4 Go-side eBPF wiring

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//   -cc clang -target bpfel \
//   KvmEvents ./kvm_events.c -- -I. -O2 -g

// eBPFCollector attaches programs and drains the ring buffer.
type eBPFCollector struct {
    objs   KvmEventsObjects
    reader *ringbuf.Reader
    links  []link.Link
}

func NewEBPFCollector() (*eBPFCollector, error) {
    if err := probeSupport(); err != nil {
        return nil, fmt.Errorf("ebpf unavailable: %w", err)
    }
    var objs KvmEventsObjects
    if err := LoadKvmEventsObjects(&objs, &ebpf.CollectionOptions{
        Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelError},
    }); err != nil {
        return nil, err
    }
    // attach tracepoints
    l1, _ := link.Tracepoint("kvm", "kvm_exit",   objs.HandleKvmExit, nil)
    l2, _ := link.Tracepoint("kvm", "kvm_entry",  objs.HandleKvmEntry, nil)
    // ...
    rd, _ := ringbuf.NewReader(objs.KvmEvents)
    return &eBPFCollector{objs: objs, reader: rd, links: []link.Link{l1, l2}}, nil
}
```

---

## 7. TUI architecture

### 7.1 bubbletea model hierarchy

```
RootModel
├── tick (250 ms tea.Tick)
├── StatusBar          – eBPF status, connection status, timestamp
├── DomainListPanel    – main view, sortable table
│   └── columns: Name | State | vCPUs | CPU% | Mem | Net↓ | Net↑ | Disk I/O
└── DetailView (overlay, activated with Enter)
    ├── CPUPanel        – per-vCPU horizontal bars
    ├── MemPanel        – alloc / available / RSS / minor faults / major faults
    ├── NetPanel        – per-NIC sparklines (last 60 samples)
    ├── IOPanel         – per-disk sparklines
    ├── KVMPanel        – exit reason bar chart (top-10 reasons)
    └── MigrationPanel  – progress bar + dirty rate + downtime estimate
```

### 7.2 Key bindings

| Key | Action |
|---|---|
| `↑` / `↓` | Navigate domain list |
| `Enter` | Open detail view |
| `Esc` / `q` | Close detail / quit |
| `Tab` | Cycle detail panel |
| `s` | Cycle sort column |
| `r` | Reverse sort order |
| `p` | Pause/resume refresh |
| `l` | Toggle log overlay |
| `?` | Help overlay |

### 7.3 Rendering pipeline

```
tea.Tick (250ms)
    │
    ▼
Model.Update(tickMsg)
    ├── store.Snapshot()      ← RLock, copy, RUnlock
    └── return updated model

Model.View()
    ├── StatusBar.Render()
    ├── DomainListPanel.Render(snapshots)
    └── if focused:
        └── DetailView.Render(store.History(focusedID))
```

The store read in `Update` is the only synchronization point. All rendering is pure (no locks held during `View()`).

### 7.4 Sparkline rendering

Sparklines use Unicode block characters (`▁▂▃▄▅▆▇█`) computed from the ring buffer. Width is dynamic based on terminal columns.

---

## 8. Cross-distro compatibility matrix

| Feature | RHEL 8.6 | RHEL 9.x | Ubuntu 20.04 | Ubuntu 22.04 |
|---|---|---|---|---|
| libvirt socket | ✓ | ✓ | ✓ | ✓ |
| `/proc` collection | ✓ | ✓ | ✓ | ✓ |
| QMP socket | ✓ | ✓ | ✓ | ✓ |
| eBPF CO-RE | ✓ (kernel 4.18+BTF) | ✓ | ✓ (kernel 5.4) | ✓ (kernel 5.15) |
| `kvm_dirty_ring` | ✗ (kernel < 5.11) | ✓ | ✗ (LTS 20.04) | ✓ |
| `kvm_halt_poll_ns` | ✓ | ✓ | ✓ | ✓ |
| SELinux considerations | Must run as `unconfined` or with `bpf_t` policy | Same | Not applicable | Not applicable |
| CAP required | `CAP_BPF` + `CAP_PERFMON` (kernel 5.8+) or `CAP_SYS_ADMIN` | Same | `CAP_SYS_ADMIN` | `CAP_BPF` + `CAP_PERFMON` |

**RHEL 8 note:** kernel 4.18 ships with BTF only from RHEL 8.6 (kernel 4.18.0-372+). Earlier 8.x kernels will fall back to proc-only mode for eBPF metrics.

**Runtime privilege:** The recommended deployment is a systemd unit with `AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN` and `NoNewPrivileges=true`. Interactive use requires `sudo` or the same capabilities on the user.

---

## 9. Development timeline

> Estimated for **one developer**, working on this as a primary project.  
> Phases are sequential; each ships a working, testable artifact.

### Phase 0 — Scaffold (week 1)

**Goal:** compile, run, show a placeholder TUI.

| Task | Detail |
|---|---|
| `go mod init`, module layout | Set up all packages as empty stubs |
| `DomainStore` + `RingBuffer` | Core data model, fully unit-tested |
| `Collector` interface | Interface + registry, ticker loop in `main.go` |
| bubbletea root model | Static "loading…" view, 250ms tick |
| Makefile skeleton | `make build`, `make test`, `make lint` (golangci-lint) |
| CI (GitHub Actions) | Build + test on `ubuntu-latest` |

**Deliverable:** binary that compiles, connects to nothing, shows placeholder.

---

### Phase 1 — libvirt integration (weeks 2–3)

**Goal:** live domain list with CPU + memory stats; no eBPF yet.

| Task | Technology | Detail |
|---|---|---|
| `LibvirtCollector` | `go-libvirt` | Domain list, state, vCPU time delta, balloon mem |
| `ProcCollector` | `prometheus/procfs` | QEMU PID discovery, page faults, host RSS |
| `DomainListPanel` | `bubbletea/bubbles/table` | Columns: name, state, CPU%, mem alloc/avail |
| `CPUPanel` | lipgloss bars | Per-vCPU horizontal bar chart |
| `MemPanel` | lipgloss layout | alloc, available, RSS, minor/major faults |
| Reconnect logic | stdlib backoff | Libvirt socket reconnect on disconnect |

**Deliverable:** functional htop-like list of KVM domains with CPU and memory.

---

### Phase 2 — Network & I/O panels (week 4)

**Goal:** complete the "stable API" metrics.

| Task | Technology | Detail |
|---|---|---|
| `NetPanel` | lipgloss + ring buffer | Per-NIC sparklines, rx/tx rates in KB/s |
| `IOPanel` | lipgloss + ring buffer | Per-disk sparklines, rd/wr rates |
| Summary columns | DomainListPanel | Add Net↓↑ and Disk I/O columns to main list |
| Sort + keybindings | bubbletea keys | Full sort, reverse, pause, help |

**Deliverable:** complete non-eBPF feature set. Usable on any distro without privilege.

---

### Phase 3 — eBPF: KVM events (weeks 5–6)

**Goal:** KVM exit reason histogram + IRQ injection stats via eBPF.

| Task | Technology | Detail |
|---|---|---|
| `vmlinux.h` generation | `bpftool btf dump` | Generate from target kernels; commit for CI |
| BPF C source | clang + CO-RE | `kvm_exit`, `kvm_entry`, `kvm_inj_virq` tracepoints |
| `bpf2go` wiring | `cilium/ebpf` | Go skeleton generation, embed ELF |
| `eBPFCollector` | `cilium/ebpf` | Attach, drain ring buffer, update store |
| Capability probe | `golang.org/x/sys/unix` | Probe `CAP_BPF`, `CAP_SYS_ADMIN`, BTF presence |
| SELinux fallback | `unix.Errno` | Detect `EPERM`, log, disable gracefully |
| `KVMPanel` | lipgloss bar chart | Top-10 exit reasons, count + percentage |
| eBPF status in header | StatusBar | `eBPF ✓ / ✗` indicator |

**Deliverable:** KVM event panel active when eBPF is available; silent no-op otherwise.

---

### Phase 4 — eBPF: page faults + halt polling (week 7)

**Goal:** complete eBPF metric surface.

| Task | Technology | Detail |
|---|---|---|
| `kvm_mmu_page_fault` probe | BPF tracepoint | Guest MMU faults, augments `/proc` data |
| `kvm_halt_poll_ns` probe | BPF tracepoint | Halt-poll time per vCPU |
| `handle_mm_fault` kprobe | BPF kprobe | Fallback page fault counter filtered by PID |
| Per-vCPU halt-poll in CPUPanel | lipgloss | Extra row below CPU bar |
| `target_pids` map management | eBPFCollector | Update map when domains start/stop |

**Deliverable:** enriched CPU and memory panels with eBPF-sourced fault data.

---

### Phase 5 — Migration panel + QMP (week 8)

**Goal:** live migration monitoring.

| Task | Technology | Detail |
|---|---|---|
| `QMPCollector` | stdlib net + JSON | Connect to QEMU monitor socket per domain |
| `query-migrate` polling | QMP | dirty pages, total pages, mbps, downtime, status |
| `kvm_dirty_ring_push` probe | BPF tracepoint (≥ 5.11) | High-resolution dirty page events |
| `MigrationPanel` | lipgloss progress bar | Phases, dirty rate graph, ETA, downtime |
| Migration state detection | LibvirtCollector | Activate QMP collector only during migration |
| Domain list migration indicator | DomainListPanel | `⇄` indicator in state column during migration |

**Deliverable:** full migration monitoring for in-progress live migrations.

---

### Phase 6 — Polish, packaging, docs (week 9–10)

**Goal:** production-ready release.

| Task | Detail |
|---|---|
| Structured logging (`log/slog`) | Log to `~/.local/share/hyperview/kvmtop.log`, not stdout |
| `--log-level` flag | debug / info / warn / error |
| `--interval` flag | Override 250ms default |
| `--domain` flag | Filter to specific domain on start |
| Help overlay (`?`) | Full keybinding reference rendered in TUI |
| Log overlay (`l`) | Last N log lines shown in TUI |
| `nfpm.yaml` | RPM + DEB spec; systemd unit file |
| `Makefile: package` | `make rpm`, `make deb` via nFPM |
| `README.md` | Install, usage, capability requirements, distro notes |
| Integration test harness | Mock libvirt socket + mock `/proc` tree for CI |
| GitHub release action | Tag → build → attach RPM/DEB/binary |

**Deliverable:** v1.0.0 release with RPM, DEB, and static binary.

---

### Timeline summary

```
Week  1    Phase 0  Scaffold + data model
Week  2-3  Phase 1  libvirt + proc collectors, CPU + mem TUI
Week  4    Phase 2  Net + I/O panels, full keybindings
Week  5-6  Phase 3  eBPF KVM events panel
Week  7    Phase 4  eBPF page faults + halt polling
Week  8    Phase 5  QMP + migration panel
Week  9-10 Phase 6  Polish, packaging, docs, release
```

Total: ~10 weeks to v1.0.0.

---

## 10. Build & packaging

### Makefile targets

```makefile
BPF_SRC   := internal/bpf/kvm_events.c
BPF_OBJ   := internal/bpf/kvm_events_bpfel.go

.PHONY: all build test lint bpf generate package rpm deb clean

all: bpf build

bpf:
 clang -target bpf -O2 -g \
   -I internal/bpf \
   -c $(BPF_SRC) -o /dev/null   # validate only; bpf2go does real compile
 go generate ./internal/bpf/...

build:
 CGO_ENABLED=0 go build \
   -ldflags="-X hyperview/internal/version.Version=$$(git describe --tags)" \
   -o bin/hyperview ./cmd/kvmtop

test:
 go test ./...

lint:
 golangci-lint run

package: rpm deb

rpm:
 nfpm package --packager rpm --target dist/

deb:
 nfpm package --packager deb --target dist/

clean:
 rm -rf bin/ dist/ internal/bpf/*_bpf*.go internal/bpf/*.o
```

### Runtime capability requirements

```ini
# /etc/systemd/system/hyperview.service
[Service]
ExecStart=/usr/bin/hyperview
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
NoNewPrivileges=true
User=hyperview
Group=libvirt
```

---

## 11. Testing strategy

| Layer | Approach |
|---|---|
| `RingBuffer` | Table-driven unit tests, 100% coverage |
| `DomainStore` | Race-detector tests (`go test -race`) |
| `LibvirtCollector` | Mock libvirt RPC socket (record/replay) |
| `ProcCollector` | Synthetic `/proc` tree under `testdata/` |
| `eBPFCollector` | Skipped in CI (requires kernel); manual test matrix per distro |
| `QMPCollector` | Mock Unix socket server returning canned JSON |
| TUI panels | `bubbletea/teatest` for headless rendering assertions |
| Integration | Docker-in-VM with a real libvirt + QEMU setup (manual, pre-release) |

---

## 12. Open questions / future work

| Item | Notes |
|---|---|
| **Multi-host support** | Add `--uri qemu+ssh://host/system` flag; libvirt already supports remote URIs |
| **Guest-agent metrics** | CPU steal, filesystem stats via `qemu-guest-agent` — requires in-guest agent |
| **Config file** | `~/.config/hyperview/config.toml` for persistent column layout, color theme |
| **Export mode** | `--output json` for scripting / pipe to other tools |
| **Prometheus exporter** | `--metrics-addr :9101` side-car mode |
| **NUMA awareness** | Per-NUMA-node vCPU pinning display |
| **ARM64 support** | BPF CO-RE is architecture-agnostic; only needs testing |
| **Container/cgroups** | Extend ProcCollector to correlate with cgroup v2 stats |
