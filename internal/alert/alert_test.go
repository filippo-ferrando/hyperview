package alert

import (
	"fmt"
	"testing"
	"time"

	"hyperview/internal/config"
)

func testEngine() *Engine {
	return NewEngine(config.Default().Alerts)
}

func sample(v float64) Sample {
	return Sample{Rule: "r", DomainID: "d", Subject: "s", Value: v,
		Level: config.Level{Warn: 10, Crit: 20}, Format: func(v float64) string { return fmt.Sprint(v) }}
}

func TestConditionHysteresis(t *testing.T) {
	e := testEngine()
	var got []Transition
	e.Subscribe(func(a Alert, tr Transition) { got = append(got, tr) })
	t0 := time.Unix(1000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

	e.Evaluate(at(0), []Sample{sample(15)})
	e.Evaluate(at(2), []Sample{sample(15)})
	if len(e.Active()) != 0 {
		t.Fatal("raised before raise_after")
	}
	e.Evaluate(at(3), []Sample{sample(15)})
	if a := e.Active(); len(a) != 1 || a[0].Severity != Warning {
		t.Fatalf("expected warning, got %+v", a)
	}
	// Escalation needs to hold too.
	e.Evaluate(at(4), []Sample{sample(25)})
	e.Evaluate(at(7), []Sample{sample(25)})
	if a := e.Active(); a[0].Severity != Critical {
		t.Fatalf("expected critical, got %v", a[0].Severity)
	}
	// 9 is below warn but above the clear level (8): stays active.
	e.Evaluate(at(8), []Sample{sample(9)})
	e.Evaluate(at(30), []Sample{sample(9)})
	if len(e.Active()) != 1 {
		t.Fatal("cleared above the clear level")
	}
	e.Evaluate(at(31), []Sample{sample(1)})
	e.Evaluate(at(40), []Sample{sample(1)})
	if len(e.Active()) != 1 {
		t.Fatal("cleared before clear_after")
	}
	e.Evaluate(at(41), []Sample{sample(1)})
	if len(e.Active()) != 0 {
		t.Fatal("not cleared")
	}
	want := []Transition{Raised, Escalated, Cleared}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("transitions %v, want %v", got, want)
	}
	if r := e.Recent(0); len(r) != 1 || r[0].Active || r[0].Resolved.IsZero() {
		t.Fatalf("resolved alert not in history: %+v", r)
	}
}

func TestConditionLowerWorse(t *testing.T) {
	s := Sample{Level: config.Level{Warn: 10, Crit: 5}, LowerWorse: true}
	if s.severity(4) != Critical || s.severity(8) != Warning || s.severity(50) != Info {
		t.Fatal("lower-is-worse severity wrong")
	}
	if s.clear(11, 0.8) || !s.clear(13, 0.8) {
		t.Fatal("lower-is-worse clear level should be warn/ratio")
	}
}

func TestConditionResolvesWhenSubjectGone(t *testing.T) {
	e := testEngine()
	t0 := time.Unix(1000, 0)
	e.Evaluate(t0, []Sample{sample(30)})
	e.Evaluate(t0.Add(5*time.Second), []Sample{sample(30)})
	if len(e.Active()) != 1 {
		t.Fatal("not raised")
	}
	e.Evaluate(t0.Add(6*time.Second), nil)
	if len(e.Active()) != 0 {
		t.Fatal("not resolved after subject disappeared")
	}
}

func TestEventDedup(t *testing.T) {
	e := testEngine()
	t0 := time.Unix(1000, 0)
	e.Raise(Alert{Rule: "x", DomainID: "d", Severity: Warning, Last: t0})
	e.Raise(Alert{Rule: "x", DomainID: "d", Severity: Critical, Last: t0.Add(10 * time.Second)})
	r := e.Recent(0)
	if len(r) != 1 || r[0].Count != 2 || r[0].Severity != Critical {
		t.Fatalf("dedup failed: %+v", r)
	}
	if c := e.DomainCounts()["d"]; c.N != 1 || c.Worst != Critical {
		t.Fatalf("domain counts %+v", c)
	}
	e.Raise(Alert{Rule: "x", DomainID: "d", Severity: Warning, Last: t0.Add(2 * time.Minute)})
	if r := e.Recent(0); len(r) != 2 {
		t.Fatalf("expected a new alert after the dedup window, got %d", len(r))
	}
}

func TestMute(t *testing.T) {
	cfg := config.Default().Alerts
	cfg.Mute = []string{"x"}
	e := NewEngine(cfg)
	e.Raise(Alert{Rule: "x"})
	if len(e.Recent(0)) != 0 {
		t.Fatal("muted rule raised")
	}
}
