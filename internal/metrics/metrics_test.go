package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"hyperview/internal/alert"
	"hyperview/internal/config"
	"hyperview/internal/store"
)

func TestCollector(t *testing.T) {
	s := store.NewDomainStore()
	s.SetHost(store.HostStat{CPUPercent: 12, MemTotalKiB: 1024, PSI: store.PSIStat{Available: true, CPUSome: 1},
		Disks: []store.HostDisk{{Name: "nvme0n1", IOPS: 10, P99Us: 2000}}})
	for _, id := range []string{"pid-1-1", "pid-2-2"} {
		s.Upsert(id, func(d *store.DomainSnapshot) {
			d.Name, d.Source, d.State, d.PID = "same-name", "qemu", "running", 1 // same name, no UUID
			d.VCPUs = []store.VCPUStat{{Index: 0, CPUPercent: 50, RunqP99Us: 300}}
			d.Ifaces = []store.IfaceStat{{Name: "tap0", RxBps: 100, DropReasons: map[string]float64{"TAP_FILTER": 1}}}
			d.Disks = []store.DiskStat{{Dev: "(all)", RdBps: 5, ErrsTotal: -1}}
			d.KVM = store.KVMStat{Available: true, ExitReasons: map[string]float64{"HLT": 10}}
		})
	}
	eng := alert.NewEngine(config.Default().Alerts)
	c := NewCollector(Sources{Store: s, Alerts: eng, Version: "test"})
	eng.Raise(alert.Alert{Rule: "vm.signal", Severity: alert.Critical, Category: alert.CatLifecycle, Last: time.Now()})

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}
	problems, err := testutil.CollectAndLint(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("lint %s: %s", p.Metric, p.Text)
	}
	if n := testutil.CollectAndCount(c, "hyperview_vm_cpu_usage_percent"); n != 2 {
		t.Errorf("vm_cpu series = %d, want 2", n)
	}
	want := `
# HELP hyperview_alerts_raised_total Alerts raised since start.
# TYPE hyperview_alerts_raised_total counter
hyperview_alerts_raised_total{category="lifecycle",rule="vm.signal",severity="critical"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "hyperview_alerts_raised_total"); err != nil {
		t.Error(err)
	}
}
