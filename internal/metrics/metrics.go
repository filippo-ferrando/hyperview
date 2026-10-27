// Package metrics exposes hyperview's data in the Prometheus format. Values
// are read from the store at scrape time. Rates are the per-second values
// hyperview computed over its last collection interval, exported as gauges;
// cumulative counters are exported as counters.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"hyperview/internal/alert"
	"hyperview/internal/probe"
	"hyperview/internal/store"
)

// DefaultListen is used when --listen is given without an address.
const DefaultListen = ":9850"

const ns = "hyperview"

// Sources is what the collector reads; functions may be nil.
type Sources struct {
	Store   *store.DomainStore
	Alerts  *alert.Engine
	Probes  func() []probe.Status
	EBPF    func() (bool, string)
	Kmsg    func() string
	Version string
}

type desc struct{ *prometheus.Desc }

func newDesc(name, help string, labels ...string) desc {
	return desc{prometheus.NewDesc(ns+"_"+name, help, labels, nil)}
}

var (
	vmLabels   = []string{"domain", "id", "source"}
	withVM     = func(extra ...string) []string { return append(append([]string{}, vmLabels...), extra...) }
	dBuildInfo = newDesc("build_info", "Build information.", "version")
	dEBPF      = newDesc("ebpf_enabled", "1 when eBPF probes are loaded.")
	dKmsg      = newDesc("kmsg_following", "1 when the kernel log is being followed.")
	dProbe     = newDesc("probe_attached", "1 when the eBPF probe is attached.", "feature", "probe", "state")

	dHostCPU     = newDesc("host_cpu_usage_percent", "Host CPU utilization over the last interval.")
	dHostCPUs    = newDesc("host_cpus", "Online host CPUs.")
	dHostLoad    = newDesc("host_load1", "Host 1-minute load average.")
	dHostMem     = newDesc("host_memory_bytes", "Host memory.", "kind")
	dHostPSI     = newDesc("host_pressure_avg10_percent", "Pressure stall information, avg10.", "resource", "kind")
	dHostUptime  = newDesc("host_uptime_seconds", "Host uptime.")
	dDiskIOPS    = newDesc("host_disk_iops", "Completed block requests per second (eBPF).", "device")
	dDiskLat     = newDesc("host_disk_request_latency_seconds", "Block request latency over the last window (eBPF).", "device", "stat")
	dDiskErrors  = newDesc("host_disk_errors_total", "Failed block requests since the probes were loaded (eBPF).", "device")
	dVMInfo      = newDesc("vm_info", "VM metadata; always 1.", withVM("uuid", "pid", "state", "reason")...)
	dVMRunning   = newDesc("vm_running", "1 when the VM is running.", vmLabels...)
	dVMVCPUs     = newDesc("vm_vcpus", "Number of vCPUs.", vmLabels...)
	dVMCPU       = newDesc("vm_cpu_usage_percent", "VM CPU usage, 100 per fully used vCPU.", vmLabels...)
	dVMMem       = newDesc("vm_memory_bytes", "VM memory by kind (max, balloon, guest_available, guest_usable, guest_unused, host_rss).", withVM("kind")...)
	dVMSwap      = newDesc("vm_guest_swap_bytes_per_second", "Guest swap traffic.", withVM("direction")...)
	dVMFaults    = newDesc("vm_host_page_faults_per_second", "Page faults of the hypervisor process.", withVM("type")...)
	dVMHugeFail  = newDesc("vm_hugetlb_failures_total", "Guest hugetlb allocation failures.", vmLabels...)
	dNetBytes    = newDesc("vm_network_bytes_per_second", "Interface throughput from the guest's point of view.", withVM("interface", "direction")...)
	dNetPkts     = newDesc("vm_network_packets_per_second", "Interface packet rate.", withVM("interface", "direction")...)
	dNetErrs     = newDesc("vm_network_errors_total", "Interface errors.", withVM("interface", "direction")...)
	dNetDrops    = newDesc("vm_network_drops_total", "Interface drops reported by the hypervisor.", withVM("interface", "direction")...)
	dNetKDrops   = newDesc("vm_network_kernel_drops_per_second", "Packets dropped by the host kernel on the interface (eBPF).", withVM("interface", "reason")...)
	dDiskBytes   = newDesc("vm_disk_bytes_per_second", "Disk throughput.", withVM("device", "direction")...)
	dDiskOps     = newDesc("vm_disk_iops", "Disk operations per second.", withVM("device", "direction")...)
	dVMDiskErrs  = newDesc("vm_disk_errors_total", "Failed disk operations reported by the hypervisor.", withVM("device")...)
	dVMBlkLat    = newDesc("vm_block_latency_seconds", "Latency of block requests issued by the hypervisor process (eBPF).", withVM("stat")...)
	dExits       = newDesc("vm_kvm_exits_per_second", "VM exits by reason (eBPF).", withVM("reason")...)
	dUExits      = newDesc("vm_kvm_userspace_exits_per_second", "KVM_RUN returns to userspace by KVM_EXIT reason (eBPF).", withVM("reason")...)
	dKVMRates    = newDesc("vm_kvm_events_per_second", "KVM event rates (eBPF).", withVM("event")...)
	dEmulFail    = newDesc("vm_kvm_emulation_failures_total", "Instruction emulation failures (eBPF).", vmLabels...)
	dVCPUCPU     = newDesc("vcpu_cpu_usage_percent", "vCPU thread CPU usage.", withVM("vcpu")...)
	dVCPUExits   = newDesc("vcpu_kvm_exits_per_second", "VM exits per vCPU (eBPF).", withVM("vcpu")...)
	dVCPURunq    = newDesc("vcpu_runqueue_latency_seconds", "Scheduler run-queue delay of the vCPU thread (eBPF).", withVM("vcpu", "stat")...)
	dMigration   = newDesc("vm_migration_info", "Migration job; always 1 while one is reported.", withVM("operation", "status")...)
	dMigBytes    = newDesc("vm_migration_memory_bytes", "Migration memory progress.", withVM("kind")...)
	dMigRate     = newDesc("vm_migration_bandwidth_bytes_per_second", "Migration bandwidth.", vmLabels...)
	dMigDirty    = newDesc("vm_migration_dirty_pages_per_second", "Guest page dirtying rate during migration.", vmLabels...)
	dMigDowntime = newDesc("vm_migration_expected_downtime_seconds", "Expected downtime of the migration switchover.", vmLabels...)
	dAlerts      = newDesc("alerts_active", "Active condition alerts.", "severity", "category", "rule")
	dAlertsTotal = newDesc("alerts_raised_total", "Alerts raised since start.", "severity", "category", "rule")
)

type alertKey struct{ severity, category, rule string }

// Collector implements prometheus.Collector over hyperview's store.
type Collector struct {
	src Sources

	mu     sync.Mutex
	raised map[alertKey]float64
}

func NewCollector(src Sources) *Collector {
	c := &Collector{src: src, raised: make(map[alertKey]float64)}
	if src.Alerts != nil {
		src.Alerts.Subscribe(func(a alert.Alert, t alert.Transition) {
			if t != alert.Raised {
				return
			}
			c.mu.Lock()
			c.raised[alertKey{a.Severity.String(), string(a.Category), a.Rule}]++
			c.mu.Unlock()
		})
	}
	return c
}

// Describe sends no descriptors, making this an unchecked collector: label
// sets depend on the VMs present.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	g := func(d desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d.Desc, prometheus.GaugeValue, v, labels...)
	}
	ctr := func(d desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d.Desc, prometheus.CounterValue, v, labels...)
	}
	b2f := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}

	g(dBuildInfo, 1, c.src.Version)
	if c.src.EBPF != nil {
		ok, _ := c.src.EBPF()
		g(dEBPF, b2f(ok))
	}
	if c.src.Kmsg != nil {
		g(dKmsg, b2f(c.src.Kmsg() == ""))
	}
	if c.src.Probes != nil {
		for _, p := range c.src.Probes() {
			g(dProbe, b2f(p.State == probe.Attached), p.Feature, p.Probe, p.State.String())
		}
	}

	h := c.src.Store.Host()
	g(dHostCPU, h.CPUPercent)
	g(dHostCPUs, float64(h.CPUs))
	g(dHostLoad, h.Load1)
	g(dHostUptime, h.Uptime.Seconds())
	g(dHostMem, kib(h.MemTotalKiB), "total")
	g(dHostMem, kib(h.MemAvailKiB), "available")
	g(dHostMem, kib(h.SwapTotalKiB), "swap_total")
	g(dHostMem, kib(h.SwapFreeKiB), "swap_free")
	if h.PSI.Available {
		g(dHostPSI, h.PSI.CPUSome, "cpu", "some")
		g(dHostPSI, h.PSI.MemSome, "memory", "some")
		g(dHostPSI, h.PSI.MemFull, "memory", "full")
		g(dHostPSI, h.PSI.IOSome, "io", "some")
		g(dHostPSI, h.PSI.IOFull, "io", "full")
	}
	for _, d := range h.Disks {
		g(dDiskIOPS, d.IOPS, d.Name)
		g(dDiskLat, us(d.AvgUs), d.Name, "avg")
		g(dDiskLat, us(d.P99Us), d.Name, "p99")
		g(dDiskLat, us(d.MaxUs), d.Name, "max")
		ctr(dDiskErrors, float64(d.Errors), d.Name)
	}

	for _, d := range c.src.Store.Snapshot() {
		c.collectVM(&d, g, ctr)
	}

	if c.src.Alerts != nil {
		active := make(map[alertKey]float64)
		for _, a := range c.src.Alerts.Active() {
			active[alertKey{a.Severity.String(), string(a.Category), a.Rule}]++
		}
		for k, n := range active {
			g(dAlerts, n, k.severity, k.category, k.rule)
		}
		c.mu.Lock()
		for k, n := range c.raised {
			ctr(dAlertsTotal, n, k.severity, k.category, k.rule)
		}
		c.mu.Unlock()
	}
}

type emit func(d desc, v float64, labels ...string)

func (c *Collector) collectVM(d *store.DomainSnapshot, g, ctr emit) {
	vm := []string{d.Name, d.ID, d.Source}
	l := func(extra ...string) []string { return append(append([]string{}, vm...), extra...) }

	g(dVMInfo, 1, l(d.UUID, strconv.Itoa(d.PID), d.State, d.Reason)...)
	running := 0.0
	if d.Running() {
		running = 1
	}
	g(dVMRunning, running, vm...)
	g(dVMVCPUs, float64(len(d.VCPUs)), vm...)
	g(dVMCPU, d.CPUPercent(), vm...)

	m := d.Mem
	for _, kv := range []struct {
		kind string
		v    uint64
	}{{"max", m.MaxKiB}, {"balloon", m.BalloonKiB}, {"guest_available", m.AvailableKiB},
		{"guest_usable", m.UsableKiB}, {"guest_unused", m.UnusedKiB}, {"host_rss", m.RssKiB}} {
		if kv.v > 0 {
			g(dVMMem, kib(kv.v), l(kv.kind)...)
		}
	}
	g(dVMSwap, m.SwapInRate*1024, l("in")...)
	g(dVMSwap, m.SwapOutRate*1024, l("out")...)
	g(dVMFaults, m.MajorFltRate, l("major")...)
	g(dVMFaults, m.MinorFltRate, l("minor")...)
	ctr(dVMHugeFail, float64(m.HugetlbFail), vm...)

	for _, i := range d.Ifaces {
		g(dNetBytes, i.RxBps, l(i.Name, "rx")...)
		g(dNetBytes, i.TxBps, l(i.Name, "tx")...)
		g(dNetPkts, i.RxPps, l(i.Name, "rx")...)
		g(dNetPkts, i.TxPps, l(i.Name, "tx")...)
		ctr(dNetErrs, float64(i.RxErrs), l(i.Name, "rx")...)
		ctr(dNetErrs, float64(i.TxErrs), l(i.Name, "tx")...)
		ctr(dNetDrops, float64(i.RxDrops), l(i.Name, "rx")...)
		ctr(dNetDrops, float64(i.TxDrops), l(i.Name, "tx")...)
		for reason, r := range i.DropReasons {
			g(dNetKDrops, r, l(i.Name, reason)...)
		}
	}
	for _, dk := range d.Disks {
		g(dDiskBytes, dk.RdBps, l(dk.Dev, "read")...)
		g(dDiskBytes, dk.WrBps, l(dk.Dev, "write")...)
		g(dDiskOps, dk.RdIOPS, l(dk.Dev, "read")...)
		g(dDiskOps, dk.WrIOPS, l(dk.Dev, "write")...)
		if dk.ErrsTotal >= 0 {
			ctr(dVMDiskErrs, float64(dk.ErrsTotal), l(dk.Dev)...)
		}
	}

	if k := d.KVM; k.Available {
		g(dVMBlkLat, us(d.BlkLatAvgUs), l("avg")...)
		g(dVMBlkLat, us(d.BlkLatP99Us), l("p99")...)
		for reason, r := range k.ExitReasons {
			g(dExits, r, l(reason)...)
		}
		for reason, r := range k.UserExits {
			g(dUExits, r, l(reason)...)
		}
		g(dKVMRates, k.IRQRate, l("irq_injection")...)
		g(dKVMRates, k.ExceptionRate, l("exception_injection")...)
		g(dKVMRates, k.HaltPollRate, l("halt_poll_success")...)
		g(dKVMRates, k.HaltWaitRate, l("halt_wait")...)
		ctr(dEmulFail, float64(k.EmulFailTotal), vm...)
	}
	for _, v := range d.VCPUs {
		idx := strconv.Itoa(v.Index)
		g(dVCPUCPU, v.CPUPercent, l(idx)...)
		if d.KVM.Available {
			g(dVCPUExits, v.ExitRate, l(idx)...)
			g(dVCPURunq, us(v.RunqAvgUs), l(idx, "avg")...)
			g(dVCPURunq, us(v.RunqP99Us), l(idx, "p99")...)
			g(dVCPURunq, us(v.RunqMaxUs), l(idx, "max")...)
		}
	}
	if mg := d.Migration; mg != nil {
		g(dMigration, 1, l(mg.Operation, mg.Status)...)
		g(dMigBytes, float64(mg.MemTotal), l("total")...)
		g(dMigBytes, float64(mg.MemProcessed), l("processed")...)
		g(dMigBytes, float64(mg.MemRemaining), l("remaining")...)
		g(dMigRate, float64(mg.Bps), vm...)
		g(dMigDirty, float64(mg.DirtyPageRate), vm...)
		g(dMigDowntime, float64(mg.ExpectedDownMs)/1000, vm...)
	}
}

func kib(v uint64) float64 { return float64(v) * 1024 }
func us(v float64) float64 { return v / 1e6 }

// Serve exposes /metrics on addr until ctx is done.
func Serve(ctx context.Context, addr string, c *Collector) error {
	reg := prometheus.NewRegistry()
	reg.MustRegister(c, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>hyperview</title></head><body><h1>hyperview</h1><p><a href="/metrics">Metrics</a></p></body></html>`))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	slog.Info("serving Prometheus metrics", slog.String("addr", ln.Addr().String()))
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
