package collect

import "time"

type rateSample struct {
	v    float64
	t    time.Time
	tick uint64
}

// rateTracker turns monotonically increasing counters into per-second rates.
// Keys not refreshed during a tick are dropped by sweep.
type rateTracker struct {
	prev map[string]rateSample
	tick uint64
}

func newRateTracker() *rateTracker {
	return &rateTracker{prev: make(map[string]rateSample)}
}

// rate returns the per-second rate of counter key since the previous call.
// The first observation and counter resets yield 0.
func (r *rateTracker) rate(key string, v float64, now time.Time) float64 {
	p, ok := r.prev[key]
	r.prev[key] = rateSample{v: v, t: now, tick: r.tick}
	if !ok || v < p.v {
		return 0
	}
	dt := now.Sub(p.t).Seconds()
	if dt <= 0 {
		return 0
	}
	return (v - p.v) / dt
}

// delta returns the counter increase since the previous call (0 on first
// observation or reset).
func (r *rateTracker) delta(key string, v float64, now time.Time) float64 {
	p, ok := r.prev[key]
	r.prev[key] = rateSample{v: v, t: now, tick: r.tick}
	if !ok || v < p.v {
		return 0
	}
	return v - p.v
}

// sweep forgets keys that were not updated since the last sweep.
func (r *rateTracker) sweep() {
	for k, s := range r.prev {
		if s.tick != r.tick {
			delete(r.prev, k)
		}
	}
	r.tick++
}
