package config

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
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

// TestExampleConfig keeps packaging/config.toml in sync: with every key
// uncommented it must parse and equal the built-in defaults.
func TestExampleConfig(t *testing.T) {
	b, err := os.ReadFile("../../packaging/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	keyLine := regexp.MustCompile(`^#(\w+\s*=.*)$`)
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if m := keyLine.FindStringSubmatch(l); m != nil {
			l = m[1]
		}
		out = append(out, l)
	}
	p := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(p, []byte(strings.Join(out, "\n")), 0o644)
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	// An empty list in the file decodes as [] where the default is nil.
	got.Probes.Disabled = nilIfEmpty(got.Probes.Disabled)
	got.Alerts.Mute = nilIfEmpty(got.Alerts.Mute)
	if want := Default(); !reflect.DeepEqual(got, want) {
		t.Errorf("example config differs from defaults:\n got %+v\nwant %+v", got, want)
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
