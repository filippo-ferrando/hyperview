package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOverridesDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(p, []byte(`
interval = "2s"
[qmp]
enabled = true
[thresholds.runq_p99_us]
warn = 1000
`), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval.Duration != 2*time.Second || !c.QMP.Enabled {
		t.Errorf("overrides not applied: %+v", c)
	}
	if c.Thresholds.RunqP99Us.Warn != 1000 || c.Thresholds.RunqP99Us.Crit != 20_000 {
		t.Errorf("partial table should keep default crit: %+v", c.Thresholds.RunqP99Us)
	}
	if c.QMP.Interval.Duration != 5*time.Second {
		t.Errorf("default qmp interval lost")
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(p, []byte("intervl = \"2s\"\n"), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestLoadExplicitMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("explicit missing config must fail")
	}
}
