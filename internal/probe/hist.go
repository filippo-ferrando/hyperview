package probe

import (
	"time"

	"hyperview/internal/bpf"
)

// HistSlots matches HIST_SLOTS in the BPF program: slot i counts samples in
// [2^i, 2^(i+1)) microseconds, slot 0 also holds 0us.
const HistSlots = len(bpf.HyperviewHist{}.Slots)

// Hist is a cumulative log2 latency histogram in microseconds.
type Hist struct {
	Slots [HistSlots]uint64
	Count uint64
	SumUs uint64
	MaxUs uint64
}

func histFromBPF(h *bpf.HyperviewHist) Hist {
	return Hist{Slots: h.Slots, Count: h.Count, SumUs: h.SumUs, MaxUs: h.MaxUs}
}

// Sub returns the samples recorded between old and h. MaxUs cannot be
// windowed, so it is estimated from the highest non-empty slot.
func (h Hist) Sub(old Hist) Hist {
	if h.Count < old.Count {
		return h // counters were reset
	}
	var d Hist
	top := -1
	for i := range h.Slots {
		d.Slots[i] = h.Slots[i] - old.Slots[i]
		if d.Slots[i] > 0 {
			top = i
		}
	}
	d.Count = h.Count - old.Count
	d.SumUs = h.SumUs - old.SumUs
	if top >= 0 {
		d.MaxUs = min(uint64(1)<<(top+1), max(h.MaxUs, 1))
	}
	return d
}

func (h Hist) MeanUs() float64 {
	if h.Count == 0 {
		return 0
	}
	return float64(h.SumUs) / float64(h.Count)
}

// Percentile estimates the q-th quantile (0..1) by linear interpolation
// inside the log2 bucket that contains it.
func (h Hist) Percentile(q float64) float64 {
	if h.Count == 0 {
		return 0
	}
	rank := q * float64(h.Count)
	var cum float64
	for i, n := range h.Slots {
		if n == 0 {
			continue
		}
		if cum+float64(n) >= rank {
			lo := 0.0
			if i > 0 {
				lo = float64(uint64(1) << i)
			}
			hi := float64(uint64(1) << (i + 1))
			return lo + (hi-lo)*(rank-cum)/float64(n)
		}
		cum += float64(n)
	}
	return float64(uint64(1) << HistSlots)
}

type histSample struct {
	at time.Time
	h  Hist
}

// HistWindow turns cumulative histograms into sliding windows: Window
// returns the samples recorded since a snapshot at least minAge old, which
// keeps percentiles stable at short refresh intervals.
type HistWindow struct {
	minAge time.Duration
	keys   map[uint32][]histSample
	seen   map[uint32]bool
}

func NewHistWindow(minAge time.Duration) *HistWindow {
	return &HistWindow{minAge: minAge, keys: make(map[uint32][]histSample), seen: make(map[uint32]bool)}
}

func (w *HistWindow) Window(key uint32, now time.Time, cur Hist) Hist {
	w.seen[key] = true
	samples := w.keys[key]
	w.keys[key] = append(samples, histSample{at: now, h: cur})
	if len(samples) == 0 {
		return Hist{} // no baseline yet
	}
	// Use the newest snapshot that is at least minAge old (or the oldest).
	for len(samples) > 1 && now.Sub(samples[1].at) >= w.minAge {
		samples = samples[1:]
	}
	w.keys[key] = append(samples, histSample{at: now, h: cur})
	return cur.Sub(samples[0].h)
}

// Sweep forgets keys not seen since the previous Sweep.
func (w *HistWindow) Sweep() {
	for k := range w.keys {
		if !w.seen[k] {
			delete(w.keys, k)
		}
	}
	clear(w.seen)
}
