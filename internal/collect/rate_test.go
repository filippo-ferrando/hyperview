package collect

import (
	"testing"
	"time"
)

func TestRateTracker(t *testing.T) {
	r := newRateTracker()
	t0 := time.Unix(1000, 0)

	if got := r.rate("a", 100, t0); got != 0 {
		t.Fatalf("first sample: want 0, got %v", got)
	}
	if got := r.rate("a", 600, t0.Add(500*time.Millisecond)); got != 1000 {
		t.Fatalf("want 1000/s, got %v", got)
	}
	if got := r.rate("a", 10, t0.Add(time.Second)); got != 0 {
		t.Fatalf("counter reset: want 0, got %v", got)
	}

	r.sweep()
	r.rate("b", 1, t0)
	r.sweep()
	if _, ok := r.prev["a"]; ok {
		t.Fatal("stale key a should have been swept")
	}
	if _, ok := r.prev["b"]; !ok {
		t.Fatal("fresh key b should survive sweep")
	}
}
