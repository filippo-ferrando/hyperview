package probe

import (
	"math"
	"testing"
	"time"
)

func TestHistPercentile(t *testing.T) {
	var h Hist
	h.Slots[3] = 90  // [8,16) us
	h.Slots[10] = 10 // [1024,2048) us
	h.Count = 100

	if p50 := h.Percentile(0.5); p50 < 8 || p50 >= 16 {
		t.Errorf("p50 = %v, want within [8,16)", p50)
	}
	if p99 := h.Percentile(0.99); p99 < 1024 || p99 > 2048 {
		t.Errorf("p99 = %v, want within [1024,2048]", p99)
	}
	if got := (Hist{}).Percentile(0.99); got != 0 {
		t.Errorf("empty hist p99 = %v", got)
	}
}

func TestHistWindow(t *testing.T) {
	w := NewHistWindow(time.Second)
	t0 := time.Unix(0, 0)
	mk := func(n uint64) Hist {
		var h Hist
		h.Slots[2] = n
		h.Count = n
		h.SumUs = 5 * n
		return h
	}

	if d := w.Window(1, t0, mk(10)); d.Count != 0 {
		t.Fatalf("first window has no baseline, got %d", d.Count)
	}
	if d := w.Window(1, t0.Add(250*time.Millisecond), mk(20)); d.Count != 10 {
		t.Fatalf("base must stay at the first snapshot until one is 1s old, got %d", d.Count)
	}
	w.Window(1, t0.Add(1100*time.Millisecond), mk(30))
	d := w.Window(1, t0.Add(1400*time.Millisecond), mk(35))
	// The 250ms snapshot (20) is now >=1s old and becomes the base.
	if d.Count != 15 || math.Abs(d.MeanUs()-5) > 1e-9 {
		t.Fatalf("want 15 samples averaging 5us, got %d / %v", d.Count, d.MeanUs())
	}
}
