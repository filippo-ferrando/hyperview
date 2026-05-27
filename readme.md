# hyperview

[![Go Version](https://img.shields.io/badge/go-1.26.3-00ADD8.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-GPL-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://www.kernel.org/)

`hyperview` is a Go-native, `htop`-style Terminal User Interface (TUI) designed for monitoring KVM/libvirt virtual machines in real time. By leveraging direct libvirt RPC connections, `/proc` parsing, Qemu Monitor Protocol (QMP) sockets, and high-performance **eBPF (Extended Berkeley Packet Filter)** kernel instrumentation, `hyperview` provides fine-grained, low-overhead hypervisor and guest metrics at sub-second refresh rates (≤ 250ms).

## Key Features

* **Real-Time Per-Domain Dashboard:** A unified, scrollable list of all virtual machines with instant sorting on CPU usage, memory consumption, network throughput, and disk I/O.
* **eBPF-Powered KVM Insights:** Low-overhead tracking of hardware virtualization performance, exposing top KVM kernel exit reasons (e.g., `EPT_VIOLATION`, `IO_INSTR`, `HLT`, `CPUID`), vCPU run counts, and precise host-scheduling wait latencies.
* **Deep Drill-Down Analytics:** Select any virtual machine to explore dedicated analytics tabs:
    1. **vCPU Profile:** Detailed core distribution graphs, execution frequencies, and cumulative KVM guest halt-polling penalties.
    2. **Memory Matrix:** Allocation breakdowns showing balloon capacity, guest-reported availability, Host RSS working sets, and real-time page fault counters (Minor/Major deltas).
    3. **Network Analytics:** Live virtual interface monitoring accompanied by sub-second resolution download (Rx) and upload (Tx) ASCII sparklines.
    4. **Storage Block I/O:** Comprehensive read/write bandwidth counters and total request tracking per attached virtual storage device.
    5. **KVM Kernel Exits:** Live histogram of architectural guest-to-host execution switches.
    6. **Migration Progress:** Detailed progress bars, dirty page rates, network mirroring throughput, and downtime windows for active live migrations.
* **Robust Fallback Architecture:** Designed with graceful degradation. If `hyperview` runs without root privileges or on a kernel without BTF configurations, it automatically falls back to an unprivileged mode, substituting eBPF metrics with `/proc` and standard libvirt counters.

## 🛠️ Architecture Overview

`hyperview` utilizes a decoupled, concurrent collector registry architecture matching the Model-View-Update (MVU) pattern powered by Bubble Tea:

```
                      ┌───────────────────────┐
                      │    hyperview Core     │
                      └───────────┬───────────┘
                                  │ Dispatches Context
                                  ▼
        ┌─────────────────┬────────────────┬────────────────┐
        │                 │                │                │
        ▼                 ▼                ▼                ▼
┌─────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ LibvirtCollector│ │ProcCollector │ │eBPFCollector │ │ QMPCollector │
│  (pure Go RPC)  │ │   (/proc/)   │ │ (KVM Exits)  │ │ (QEMU Socket)│
└─────────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
          │                │                │                │
          └────────────────┼────────────────┘                │ (Active during
                           ▼                                 │  VM migration)
                 ┌──────────────────┐                        │
                 │   DomainStore    │◄───────────────────────┘
                 │ (RWMutex Protected)
                 └─────────┬────────┘
                           │ snapshot() thread-safe copy
                           ▼
                 ┌──────────────────┐
                 │  Bubble Tea TUI  │
                 │ (Pure Rendering) │
                 └──────────────────┘
```

1. **`LibvirtCollector`**: Establishes a pure-Go RPC layer over `/var/run/libvirt/libvirt-sock` to populate basic lifecycle state, core counts, memory boundaries, and physical hardware deltas.
2. **`ProcCollector`**: Uses `prometheus/procfs` to discover parent QEMU processes and map OS-level kernel context-switch rates and working-set RSS dimensions.
3. **`eBPFCollector`**: Deploys legacy/CO-RE BPF tracepoints into `kvm:kvm_exit` and `kvm:kvm_entry` subsystems to stream sub-microsecond architectural telemetry into synchronized lockless shared maps.
4. **`QMPCollector`**: Polls active JSON-RPC channels via UNIX sockets (`/var/run/libvirt/qemu/<domain>.monitor`) exclusively during live synchronization sequences to evaluate memory mirroring dirty page states.

## ⌨️ Interactive Keyboard Controls

| Key | Context | Action |
|---|---|---|
| `↑` / `↓` | Main View | Move selector up and down the virtual machine index table. |
| `Enter` | Main View | Drill down into comprehensive metrics for the selected VM. |
| `Tab` | Detail View | Cycle through cross-sectional analytics panels (vCPU → Mem → Net → I/O → KVM → Migration). |
| `s` | Main View | Rotate column sorting forward through metrics fields (Name, State, vCPUs, CPU%, Mem, Net, Disk). |
| `r` | Main View | Toggle inverse collection list sorting logic (Ascending / Descending). |
| `p` | Global | Pause/Resume background evaluation frames without freezing the UI. |
| `l` | Global | Open/Close the real-time structured application transaction logs overlay. |
| `?` | Global | Open/Close the keyboard interactive command reference manual. |
| `Esc` | Global | Collapse open detail panels / return to the main list / dismiss modals. |
| `q` / `Ctrl+C` | Global | Terminate the application context and cleanly detach infrastructure probes. |

## ⚙️ Compilation & Development

### Prerequisites

To build the implementation from source or iterate on the eBPF kernel layer, ensure the host includes:

* **Go Compiler** (v1.22+)
* **LLVM / Clang** (For compilation of the BPF C source code into eBPF bytecode blocks)
* **`bpftool`** (Optional, used during development to refresh the embedded `vmlinux.h` system bindings)

### Build Pipeline

The orchestration of the build system is managed via the provided `Makefile`.

1. **Generate eBPF Artifacts**: Compile the BPF C source (`internal/bpf/_kvm_events.c`) and generate Go accessors via Cilium `bpf2go`:

    ```bash
    make bpf
    ```

2. **Compile Statically-Linked Binary**: Build a cross-distro compatible executable binary inside the local `bin/` directory:

    ```bash
    make build
    ```

3. **Execute the Test Suites**: Run the localized data model and concurrency race-condition tests:

    ```bash
    make test
    ```
