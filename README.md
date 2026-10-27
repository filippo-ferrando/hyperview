# hyperview

A terminal monitor for KVM virtual machines on Linux, instrumented with eBPF.
It shows what every guest is doing on the host — CPU, memory, network, disk,
KVM exits, scheduler latency — and watches the guests, the hypervisor
processes and the host kernel for problems, raising alerts as they happen.
It can also run headless, sending alerts to journald and serving Prometheus
metrics.

- Works with **any KVM userspace**: libvirt, Proxmox, plain QEMU, Firecracker,
  cloud-hypervisor, crosvm, kvmtool.
- Runs on **any distribution with Linux 5.8+ and kernel BTF** (for example
  Arch, Fedora, Debian 11+, Ubuntu 20.10+, RHEL/Alma/Rocky 9, Proxmox VE 7+),
  on **x86_64 (Intel VMX, AMD SVM) and arm64**.
- A single static binary; without root it still runs, with fewer metrics.

## What it watches

| Area | Metrics | Problems detected |
|---|---|---|
| CPU & scheduling | per-VM and per-vCPU usage, host CPU, run-queue delay (avg/p99/max) per vCPU thread, CPU pressure | vCPUs starved of host CPU, CPU pressure |
| KVM | exits/s by decoded reason (VMX, SVM, arm64 ESR), returns to userspace by `KVM_EXIT_*`, IRQ/exception injection, halt polling | exit storms, `KVM_RUN` errors, `INTERNAL_ERROR`/`FAIL_ENTRY`/`SHUTDOWN` exits, emulation failures, `#DF`/`#MC` injected into a guest |
| Memory | configured/balloon/guest usable memory, host RSS, guest swap, hypervisor page faults, memory pressure | low guest memory, guest swapping, guest RAM swapped on the host, OOM kills, hugetlb failures, host memory low |
| Disk | per-disk throughput/IOPS/errors, latency of each VM's block I/O, host device latency | slow devices, I/O errors (with sector), filesystem errors, NVMe/SCSI/ATA/md failures, I/O pressure |
| Network | per-interface throughput, packet rate, errors, drops, kernel drop reasons per tap | packet drops, interface errors, NIC transmit timeouts, link down |
| Lifecycle | state, state reason, migration progress | crashed or error-paused guests (I/O error, watchdog, panic), hypervisor crashes/kills/exits with the signal and sender, failed migrations |
| Host kernel | — | oops, `BUG`, `WARNING`, panic, soft/hard lockups, RCU stalls, hung tasks, machine checks, EDAC, PCIe AER, memory failure, thermal throttling, clocksource problems, KVM warnings |

Data comes from libvirt (when present), `/proc` and `/sys`, the hypervisors'
tap devices, eBPF probes on kernel tracepoints, `/dev/kmsg` and, optionally,
the QMP monitor of QEMU guests not managed by libvirt. See
[docs/architecture.md](docs/architecture.md) for how it fits together.

## Requirements

- Linux **5.8 or newer** with BTF (`/sys/kernel/btf/vmlinux`, i.e.
  `CONFIG_DEBUG_INFO_BTF=y`, the default on current distributions).
- **root** (or `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_SYSLOG`) for
  eBPF, the kernel log and other users' hypervisor processes.
  Without it hyperview runs with libvirt and `/proc` data only.
- The `kvm` module loaded for KVM probes (they are skipped otherwise).
- Kernels in lockdown `confidentiality` mode block eBPF tracing; hyperview
  then runs without it.

Each probe attaches independently: a missing tracepoint (older kernel,
other architecture, `mce` on arm64) disables only the metric it feeds. The
status view (`p`) lists every probe and why it is inactive.

## Install

Packages (deb, rpm, Arch, Alpine) for amd64 and arm64 are produced by
`make package`:

```sh
sudo dpkg -i dist/hyperview_*_amd64.deb              # Debian, Ubuntu, Proxmox
sudo dnf install dist/hyperview-*.x86_64.rpm          # RHEL, Fedora, SUSE
sudo pacman -U dist/hyperview-*-x86_64.pkg.tar.zst    # Arch
sudo apk add --allow-untrusted dist/hyperview_*_x86_64.apk  # Alpine
```

They install `/usr/bin/hyperview`, `/etc/hyperview/config.toml` and a service
(systemd unit, or an OpenRC script on Alpine) that is not enabled.

From source (Go 1.26+):

```sh
make build && sudo make install
```

## Usage

```sh
sudo hyperview                      # interactive UI
sudo hyperview --headless           # alerts to journald / stdout, no UI
sudo hyperview --listen             # UI plus Prometheus metrics on :9850
sudo hyperview --headless --listen=127.0.0.1:9100
```

| Flag | Meaning |
|---|---|
| `--config FILE` | configuration file (default `/etc/hyperview/config.toml` when present) |
| `--interval D` | collection interval, e.g. `500ms` (default `1s`) |
| `--headless` | no UI; write alert transitions to journald or stdout |
| `--listen[=ADDR]` | serve `/metrics`; `--listen` alone uses `:9850` |
| `--domain NAME` | start the UI filtered on a VM name |
| `--log-level L` | `debug`, `info`, `warn`, `error` |
| `--version` | print the version |

### Interactive UI

The dashboard shows the host summary (CPU and memory history, load, swap,
pressure, disk latency, data source status), the VM table and the most
recent alerts. `Enter` opens a VM with tabs for overview, CPU, memory,
network, disk, KVM, alerts and migration. The layout adapts to the terminal
size down to about 60 columns, hiding the least important columns first.

| Key | Action |
|---|---|
| `↑` `↓` / `j` `k`, `PgUp` `PgDn`, `g` `G` | move / scroll |
| `Enter` / `→` | open the selected VM |
| `←` `→` / `h` `l` / `1`–`9` | switch detail tab |
| `Esc` / `q` | back (`q` quits from the dashboard) |
| `/` | filter VMs by name or source |
| `s` / `r` | cycle sort column (name, cpu, mem, net, disk, alerts) / reverse |
| `a` | all alerts with details; `f` sets the minimum severity |
| `p` | probe and data source status |
| `L` | internal log |
| `?` | help |

The UI logs to `~/.local/share/hyperview/hyperview.log`.

### Headless mode and systemd

```sh
sudo systemctl enable --now hyperview
journalctl -u hyperview HYPERVIEW_SEVERITY=critical
```

The unit runs `hyperview --headless --listen` as root with a restricted
capability set and a read-only view of the system. Under systemd each alert
transition is a structured journal record with a priority matching its
severity and `HYPERVIEW_RULE`, `HYPERVIEW_SEVERITY`, `HYPERVIEW_CATEGORY`,
`HYPERVIEW_DOMAIN`, `HYPERVIEW_SUBJECT`, … fields. Elsewhere each transition
is one JSON object on stdout:

```json
{"time":"…","transition":"raised","id":3,"rule":"vm.signal","kind":"event","severity":"critical","category":"lifecycle","domain":"web01","subject":"tid 4312","message":"hypervisor received SIGSEGV (crash)","source":"ebpf","count":1,"active":false,…}
```

Transitions are `raised`, `escalated` (a condition changed severity),
`resolved`, and `summary` (an event that repeated, with its total count, when
its deduplication window closes).

### Prometheus

`--listen` serves `/metrics` with series prefixed `hyperview_`. VM series
carry `domain`, `id` and `source` labels.

| Metric | Labels |
|---|---|
| `host_cpu_usage_percent`, `host_load1`, `host_cpus`, `host_uptime_seconds` | |
| `host_memory_bytes` | `kind` (total, available, swap_total, swap_free) |
| `host_pressure_avg10_percent` | `resource`, `kind` |
| `host_disk_iops`, `host_disk_request_latency_seconds`, `host_disk_errors_total` | `device` (, `stat`) |
| `vm_info` | `uuid`, `pid`, `state`, `reason` |
| `vm_running`, `vm_vcpus`, `vm_cpu_usage_percent` | |
| `vm_memory_bytes` | `kind` (max, balloon, guest_available, guest_usable, guest_unused, host_rss) |
| `vm_guest_swap_bytes_per_second`, `vm_host_page_faults_per_second`, `vm_hugetlb_failures_total` | |
| `vm_network_bytes_per_second`, `vm_network_packets_per_second`, `vm_network_errors_total`, `vm_network_drops_total` | `interface`, `direction` |
| `vm_network_kernel_drops_per_second` | `interface`, `reason` |
| `vm_disk_bytes_per_second`, `vm_disk_iops`, `vm_disk_errors_total` | `device` (, `direction`) |
| `vm_block_latency_seconds` | `stat` |
| `vm_kvm_exits_per_second`, `vm_kvm_userspace_exits_per_second` | `reason` |
| `vm_kvm_events_per_second` | `event` |
| `vm_kvm_emulation_failures_total` | |
| `vcpu_cpu_usage_percent`, `vcpu_kvm_exits_per_second`, `vcpu_runqueue_latency_seconds` | `vcpu` (, `stat`) |
| `vm_migration_*` | |
| `alerts_active`, `alerts_raised_total` | `severity`, `category`, `rule` |
| `ebpf_enabled`, `kmsg_following`, `probe_attached`, `build_info` | |

Rates (`*_per_second`, `*_iops`) are computed by hyperview over its
collection interval; `*_total` series are counters.

## Configuration

Everything works without a configuration file. To change thresholds,
timings, mute rules or disable probes, edit `/etc/hyperview/config.toml`; the
[example](packaging/config.toml) lists every key with its default. Unknown
keys are rejected.

```toml
listen = ":9850"

[thresholds]
runq_p99_us = { warn = 2000, crit = 10000 }

[alerts]
mute = ["vm.appeared", "vm.disappeared"]

[qmp]
enabled = true   # Proxmox / plain QEMU: run state, per-disk stats, migration
```

Conditions (thresholds) fire after holding for `raise_after` (3s) and
resolve after staying below `threshold × clear_ratio` for `clear_after`
(10s). Repeated events are merged within `dedup` (1m).

## Alert rules

| Rule | Severity | Raised when |
|---|---|---|
| `vcpu.runq_latency` | W/C | vCPU run-queue delay p99 above threshold |
| `kvm.exit_storm` | W/C | VM exits per vCPU above threshold |
| `kvm.run_error` | W/C | `KVM_RUN` failed (`EFAULT` is critical) |
| `kvm.exit_internal_error`, `kvm.exit_fail_entry` | C | KVM cannot keep running the vCPU |
| `kvm.exit_shutdown`, `kvm.exit_memory_fault`, … | W | other abnormal `KVM_EXIT_*` |
| `kvm.exit_system_event` | I | guest asked for shutdown/reset/crash |
| `kvm.emulation_failure` | W | instruction emulation failed |
| `kvm.guest_exception` | W/C | `#DF` (W) or `#MC` (C) injected into a guest |
| `kvm.message`, `kvm.vfio` | W | KVM or VFIO warnings in the kernel log |
| `vm.crashed`, `vm.paused_error` | C | guest crashed or paused on I/O error, watchdog, panic |
| `vm.state` | I/C | state change (critical when it crashed or failed) |
| `vm.signal` | W/C | fatal signal to a hypervisor (`SIGKILL`/`SIGTERM` W with the sender) |
| `vm.process_exit` | I/W/C | hypervisor exited (killed by a signal: C) |
| `vm.segfault`, `vm.trap` | C | hypervisor crash in the kernel log |
| `vm.migration` | I/W | migration started/finished/failed |
| `vm.appeared`, `vm.disappeared` | I | VM discovered / gone |
| `mem.guest_low`, `mem.guest_swap_in`, `mem.host_major_faults`, `host.mem_low` | W/C | memory thresholds |
| `mem.oom_kill` | W/C | OOM kill (critical for a hypervisor) |
| `mem.hugetlb_fail`, `mem.alloc_failure` | W | allocation failures |
| `host.psi_cpu_some`, `host.psi_mem_some`, `host.psi_mem_full`, `host.psi_io_full` | W/C | pressure above threshold |
| `io.disk_latency`, `io.vm_latency` | W/C | block latency p99 above threshold |
| `io.disk_errors`, `io.vm_disk_errors` | C | failed I/O requests |
| `io.fs_error`, `io.nvme`, `io.scsi`, `io.md`, `io.blk_mq_hang` | C | storage errors in the kernel log |
| `io.ata` | W | ATA link errors |
| `net.drops` | W/C | interface drops above threshold |
| `net.errors` | W | interface errors |
| `net.tx_timeout` | C | NIC transmit timeout |
| `net.link_down` | W | link down |
| `kernel.oops`, `kernel.panic`, `kernel.bug`, `kernel.soft_lockup`, `kernel.hard_lockup`, `kernel.rcu_stall` | C | kernel failures |
| `kernel.warning`, `kernel.hung_task`, `kernel.hrtimer`, `kernel.clocksource`, `kernel.critical` | W | kernel warnings |
| `hw.mce` | W/C | machine check (corrected: W) |
| `hw.edac_ue`, `hw.memory_failure` | C | uncorrected memory errors |
| `hw.edac_ce`, `hw.thermal` | W | corrected memory errors, throttling |
| `hw.pcie_aer` | I/C | PCIe errors (uncorrected/fatal: C) |

I = info, W = warning, C = critical.

## Development

```sh
make build       # static binary in bin/
make build-all   # bin/hyperview-amd64, bin/hyperview-arm64
make test        # tests with the race detector
make vet         # go vet + gofmt check
make bpf         # regenerate the eBPF object (clang, libbpf headers)
make check-bpf   # fail if the committed object is stale
make package     # deb, rpm, Arch and Alpine packages in dist/
```

The eBPF program lives in `internal/bpf/src/`. The generated object
(`internal/bpf/hyperview_bpfel.o`) is committed, so a normal build needs only
Go. One little-endian object serves both amd64 and arm64; kernel structures
are accessed through CO-RE and tracepoint fields through offsets read from
tracefs at load time.

## License

GPL. The eBPF program is licensed GPL as required by the kernel helpers it
uses.
