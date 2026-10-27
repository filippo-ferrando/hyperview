# hyperview architecture

This document describes how hyperview is put together: where data comes
from, how it flows to the UI, the alert engine and the exporters, and the
choices that keep it portable across kernels and distributions.

## Overview

```
 libvirt RPC ──┐                                     ┌── Detector ──┐
 /proc scan ───┤                                     │  (thresholds) │
 tap /sys ─────┤  Poller ──► DomainStore ──Commit──► ┤               ├─► alert.Engine ─┬─► TUI
 QMP (opt-in) ─┤  (tick)     (snapshots,             │               │                 ├─► journald / JSON
 /proc/stat… ──┤             history)                └───────────────┘                 └─► Prometheus
 eBPF maps ────┘                                                         ▲
                                                                          │ events
 eBPF ring buffer ── EBPFCollector.RunEvents ── alert.FromProbeEvent ──────┤
 /dev/kmsg ──────── kmsg.Reader ─────────────── alert.FromKmsg ───────────┘
```

| Package | Role |
|---|---|
| `cmd/hyperview` | flags, configuration, wiring, run modes (UI, headless) |
| `internal/config` | defaults and TOML loading |
| `internal/collect` | discovery and collectors, the poller |
| `internal/bpf` | eBPF C source and the bpf2go-generated object and bindings |
| `internal/probe` | loading/attaching probes, reading maps, decoding |
| `internal/store` | thread-safe current state and history |
| `internal/alert` | alert engine, metric detectors, event and kernel log classifiers |
| `internal/kmsg` | `/dev/kmsg` reader |
| `internal/tui` | Bubble Tea v2 interface |
| `internal/sink` | headless outputs (journald, JSON) |
| `internal/metrics` | Prometheus collector and HTTP endpoint |

## Collection

`collect.Poller` runs once per interval (1s by default):

1. **Discoverers** report which VMs exist: `LibvirtCollector` and
   `ScanCollector`. A VM that no discoverer reports is removed from the
   store; a discoverer that fails keeps its last result for 10 seconds so a
   libvirtd restart does not make every VM blink.
2. **Collectors** fill in metrics: QMP (opt-in), host, `/proc`, eBPF.
3. `DomainStore.Commit` records one history sample per VM and for the host.
4. **After-tick hooks** run the detectors on the committed state.

Collectors write with `Mutate`/`Upsert` and only touch the fields they own,
so for example libvirt's CPU numbers and eBPF's run-queue latency for the
same vCPU coexist. Readers get deep copies from `Snapshot`.

### Discovery

- **libvirt** — pure-Go RPC (`go-libvirt`) over the libvirtd or virtqemud
  socket, read-only sockets as a fallback. Provides state and reason, vCPU
  times, balloon and memory statistics, interface and block stats, and
  migration progress from the job API. Domain XML (disks, interfaces) is
  cached for 30s.
- **Process scan** — `ProcessIndex` scans `/proc/*/fd` for
  `anon_inode:kvm-vm`, which every KVM userspace holds. Its command line
  gives the hypervisor type, name, UUID and memory; tap devices come from
  `/proc/<pid>/fdinfo` of `/dev/net/tun` descriptors. `ScanCollector`
  reports the processes libvirt does not own (matched by PID), so Proxmox,
  plain QEMU, Firecracker and cloud-hypervisor guests appear without
  configuration. Their network stats come from the taps (directions swapped
  to the guest's view), disk throughput from `/proc/<pid>/io`.
- **vCPU threads** are recognized by thread name (`CPU n/KVM` for QEMU,
  `fc_vcpu n`, `vcpu n`, …) and drive per-vCPU CPU usage and the eBPF
  per-thread maps.

### QMP (opt-in)

For QEMU guests outside libvirt, `QMPCollector` finds the server-mode QMP
socket on the command line (`-qmp unix:…,server` or a `-chardev socket,…,server`
bound to a control `-mon`, as Proxmox does) and queries `query-status`,
`query-block`/`query-blockstats` and `query-migrate`. QMP serves one client
at a time, so each poll connects, queries and disconnects within a timeout,
runs in the background, and is off by default. The first poll of a new VM
is synchronous so its first snapshot already has the real run state.

## eBPF

### Portability

The goal is one binary for every distribution running Linux 5.8+ with BTF,
on amd64 and arm64:

- **One object for both architectures.** bpf2go builds a single `bpfel`
  object. The program uses a minimal hand-written `vmlinux.h` with only the
  structures it reads, marked `preserve_access_index`, so every access is a
  CO-RE relocation resolved against the running kernel's BTF.
- **Classic tracepoints with runtime offsets.** The `kvm`, `block`, `oom` and
  `mce` tracepoints are attached as classic tracepoints. Their field offsets
  are read from tracefs `format` files at load time and passed to the
  program as `volatile const` values, so they work without kvm module BTF
  and across kernels whose event layouts differ.
- **BTF tracepoints** (`tp_btf`) are used where kernel types are needed:
  scheduler events, process exit, signal generation, `kfree_skb`. Both
  `kfree_skb` variants (with and without a drop reason, 5.17+) exist and the
  loader keeps the one the kernel accepts. `task_struct.__state` versus
  `state` is handled with `bpf_core_field_exists`.
- **Per-probe loading.** Each program is loaded and attached on its own with
  shared maps. A missing tracepoint (module not loaded, `mce` on arm64,
  older kernel) or a verifier rejection disables only that probe, and its
  status and reason are shown in the UI and exported as metrics. Features
  can also be disabled in the configuration.

### Probes and maps

| Feature | Hooks | Data |
|---|---|---|
| `kvm-exits` | `kvm:kvm_exit` | per-VM exits by raw reason, per-vCPU exit counters |
| `kvm-errors` | `kvm:kvm_userspace_exit`, `kvm_emulate_insn`, `kvm_inj_exception` | userspace exit reasons, `KVM_RUN` errors, emulation failures, injected exceptions; events for abnormal cases |
| `kvm-irq` | `kvm:kvm_inj_virq` | interrupt injection rate |
| `kvm-halt` | `kvm:kvm_vcpu_wakeup` | halt polling success vs. sleeps |
| `runqueue` | `sched_wakeup`, `sched_wakeup_new`, `sched_switch` | log2 histogram of run-queue delay per vCPU thread |
| `lifecycle` | `sched_process_exit`, `signal_generate` | hypervisor exits with status, fatal signals with sender |
| `block` | `block:block_rq_issue`, `block_rq_complete` | latency histograms per device and per VM process, errors |
| `net-drops` | `skb:kfree_skb` | drops by reason on the VMs' interfaces |
| `oom` | `oom:mark_victim` | OOM victims |
| `mce` | `mce:mce_record` | machine checks (x86) |

Only processes in the `targets` map (the hypervisor PIDs, refreshed every
tick) are instrumented, and only their interfaces in `target_ifaces`, so the
overhead does not grow with unrelated host activity. Counters are per-CPU
where hot. Discrete events go through a 256 KiB ring buffer with a 100 ms
per-process, per-type rate limit.

Exit reasons are decoded per architecture: VMX basic exit reasons, SVM exit
codes (including the CR/DR/exception ranges), and arm64 ESR exception
classes. Skb drop reason names are read from the running kernel's BTF
(`enum skb_drop_reason`), since they change between versions.

Latency percentiles come from cumulative log2 histograms: `HistWindow`
keeps recent snapshots and subtracts one at least a second old, so p99 and
the average describe a sliding window rather than all time.

## Alerts

`alert.Engine` holds two kinds of alerts:

- **Events** are one-off occurrences (a signal, an OOM kill, an oops). They
  are deduplicated by key within a window (1m): repeats increment a count.
  When the window closes on a repeated event, a `summary` transition is
  emitted with the total.
- **Conditions** compare a sampled value with warning/critical thresholds.
  A condition fires after holding for `raise_after`, can escalate or
  de-escalate while active, and resolves after staying below
  `threshold × clear_ratio` for `clear_after`. A condition whose subject
  disappears (VM gone, metric unavailable) resolves immediately.

Producers:

- `Detector` turns each committed tick into condition samples (run-queue
  latency, exit storms, memory, pressure, latency, drops, error states) and
  into events for counters that moved and state changes.
- `FromProbeEvent` classifies eBPF ring buffer events. Events are
  attributed to VMs by PID; the previous tick's PIDs are kept so the exit
  of a VM that just stopped is still attributed.
- `FromKmsg` classifies kernel log records with an ordered rule list. PIDs
  found in messages (hung tasks, OOM kills, segfaults, `kvm [pid]`) are
  resolved to VMs, including vCPU thread IDs. At startup, records from the
  last 10 minutes are replayed. The OOM rule shares its key with the eBPF
  OOM event, so the two sources merge into one alert.

Subscribers (UI log, headless sink, Prometheus counters) are registered
before any source starts, so replayed records are not missed.

## Interface

The TUI is a Bubble Tea v2 model refreshed on the collection interval. It
reads snapshots from the store and the engine and never blocks collection.
Layout is computed from the terminal size: table columns declare a
priority and flexible widths, and `layout` hides the least important
columns first; alert rows, key/value grids, the tab bar, the footer and
chart heights adapt as well. `render_test.go` renders every screen at
several sizes and fails if anything overflows.

## Outputs

- **Headless** (`--headless`): alert transitions go to journald as
  structured records when `JOURNAL_STREAM` matches stdout/stderr, otherwise
  as JSON lines on stdout. Log lines carry `<N>` priority prefixes under
  journald.
- **Prometheus** (`--listen`): an unchecked collector builds const metrics
  from the store at scrape time. Rates computed by hyperview are gauges,
  cumulative counters are counters. VMs are labeled by name, a unique id
  and source, so unmanaged VMs without a UUID never collide.

## Build

`internal/bpf/gen.go` drives bpf2go; the generated object and bindings are
committed and `make check-bpf` verifies they match the source. Binaries are
static (`CGO_ENABLED=0`). nfpm builds deb, rpm, Arch and Alpine packages from
`packaging/nfpm.yaml`; the systemd unit runs headless with a restricted
capability set, and Alpine gets an OpenRC script instead.
