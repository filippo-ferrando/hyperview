// Package config holds hyperview's settings: built-in defaults overridden by
// an optional TOML file.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultPath is read when no --config flag is given; a missing file there
// is not an error.
const DefaultPath = "/etc/hyperview/config.toml"

// Duration is a time.Duration that decodes from TOML strings like "1s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

type Config struct {
	Interval Duration `toml:"interval"`
	LogLevel string   `toml:"log_level"`

	Probes     Probes     `toml:"probes"`
	Kmsg       Kmsg       `toml:"kmsg"`
	QMP        QMP        `toml:"qmp"`
	Alerts     Alerts     `toml:"alerts"`
	Thresholds Thresholds `toml:"thresholds"`
}

type Probes struct {
	// Disabled lists eBPF features to skip (kvm-exits, runqueue, ...).
	Disabled []string `toml:"disabled"`
}

type Kmsg struct {
	Enabled bool `toml:"enabled"`
	// Replay is how far back kernel log records are reported at startup.
	Replay Duration `toml:"replay"`
}

// QMP polls the monitor socket of QEMU guests not managed by libvirt. Off by
// default: QMP sockets accept one client at a time, so polling can briefly
// block management tools such as Proxmox's qm.
type QMP struct {
	Enabled  bool     `toml:"enabled"`
	Interval Duration `toml:"interval"`
	Timeout  Duration `toml:"timeout"`
}

type Alerts struct {
	// Mute lists rule IDs that never raise alerts.
	Mute []string `toml:"mute"`
	// History is the number of alerts kept, active ones excluded.
	History int `toml:"history"`
	// Dedup merges repeats of the same event alert within this window.
	Dedup Duration `toml:"dedup"`
	// RaiseAfter is how long a condition must hold before it fires.
	RaiseAfter Duration `toml:"raise_after"`
	// ClearAfter is how long a condition must stay below its clear level
	// before it resolves.
	ClearAfter Duration `toml:"clear_after"`
	// ClearRatio places the clear level at threshold*ratio (or
	// threshold/ratio for lower-is-worse values) to avoid flapping.
	ClearRatio float64 `toml:"clear_ratio"`
}

// Level is a warning/critical threshold pair. A zero value disables that
// level.
type Level struct {
	Warn float64 `toml:"warn"`
	Crit float64 `toml:"crit"`
}

type Thresholds struct {
	RunqP99Us       Level `toml:"runq_p99_us"`        // per vCPU scheduler delay
	VCPUExitRate    Level `toml:"vcpu_exit_rate"`     // KVM exits/s per vCPU
	GuestMemFreePct Level `toml:"guest_mem_free_pct"` // usable/available, lower is worse
	GuestSwapInKiBs Level `toml:"guest_swap_in_kibs"` // guest swap-in KiB/s
	MajorFaultRate  Level `toml:"major_fault_rate"`   // hypervisor major faults/s
	HostMemFreePct  Level `toml:"host_mem_free_pct"`  // MemAvailable/MemTotal, lower is worse
	PSICPUSome      Level `toml:"psi_cpu_some"`       // avg10 %
	PSIMemSome      Level `toml:"psi_mem_some"`
	PSIMemFull      Level `toml:"psi_mem_full"`
	PSIIOFull       Level `toml:"psi_io_full"`
	DiskP99Us       Level `toml:"disk_p99_us"`     // host device request latency
	VMBlockP99Us    Level `toml:"vm_block_p99_us"` // latency of I/O issued by a VM
	NetDropRate     Level `toml:"net_drop_rate"`   // drops/s per VM interface
}

func Default() Config {
	return Config{
		Interval: Duration{time.Second},
		LogLevel: "info",
		Kmsg:     Kmsg{Enabled: true, Replay: Duration{10 * time.Minute}},
		QMP:      QMP{Enabled: false, Interval: Duration{5 * time.Second}, Timeout: Duration{500 * time.Millisecond}},
		Alerts: Alerts{
			History:    1000,
			Dedup:      Duration{time.Minute},
			RaiseAfter: Duration{3 * time.Second},
			ClearAfter: Duration{10 * time.Second},
			ClearRatio: 0.8,
		},
		Thresholds: Thresholds{
			RunqP99Us:       Level{Warn: 5_000, Crit: 20_000},
			VCPUExitRate:    Level{Warn: 100_000, Crit: 250_000},
			GuestMemFreePct: Level{Warn: 10, Crit: 5},
			GuestSwapInKiBs: Level{Warn: 1024, Crit: 10240},
			MajorFaultRate:  Level{Warn: 100, Crit: 1000},
			HostMemFreePct:  Level{Warn: 10, Crit: 5},
			PSICPUSome:      Level{Warn: 50, Crit: 80},
			PSIMemSome:      Level{Warn: 10, Crit: 30},
			PSIMemFull:      Level{Warn: 5, Crit: 15},
			PSIIOFull:       Level{Warn: 10, Crit: 30},
			DiskP99Us:       Level{Warn: 50_000, Crit: 200_000},
			VMBlockP99Us:    Level{Warn: 50_000, Crit: 200_000},
			NetDropRate:     Level{Warn: 10, Crit: 100},
		},
	}
}

// Load reads path over the defaults. An empty path reads DefaultPath and
// tolerates its absence.
func Load(path string) (Config, error) {
	cfg := Default()
	explicit := path != ""
	if !explicit {
		path = DefaultPath
	}
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	if keys := md.Undecoded(); len(keys) > 0 {
		return cfg, fmt.Errorf("config %s: unknown key %q", path, keys[0].String())
	}
	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	if c.Interval.Duration < 100*time.Millisecond {
		return fmt.Errorf("interval must be at least 100ms")
	}
	if c.Alerts.ClearRatio <= 0 || c.Alerts.ClearRatio > 1 {
		return fmt.Errorf("alerts.clear_ratio must be in (0, 1]")
	}
	if c.Alerts.History < 1 {
		return fmt.Errorf("alerts.history must be positive")
	}
	return nil
}

// ProbeDisabled converts Probes.Disabled to a set.
func (c *Config) ProbeDisabled() map[string]bool {
	m := make(map[string]bool, len(c.Probes.Disabled))
	for _, f := range c.Probes.Disabled {
		m[f] = true
	}
	return m
}
