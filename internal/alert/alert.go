// Package alert turns metrics and kernel events into deduplicated alerts.
//
// Two kinds exist. Event alerts are one-off occurrences (a signal, an OOM
// kill, a kernel oops); repeats with the same key inside the dedup window
// are merged into one alert with a count. Condition alerts track a value
// against warning/critical thresholds with hysteresis: they fire once the
// value has stayed over a threshold for RaiseAfter and resolve once it has
// stayed under the clear level for ClearAfter.
package alert

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"hyperview/internal/config"
)

type Severity int

const (
	Info Severity = iota
	Warning
	Critical
)

func (s Severity) String() string {
	return [...]string{"info", "warning", "critical"}[s]
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

type Category string

const (
	CatKVM       Category = "kvm"
	CatSched     Category = "sched"
	CatMemory    Category = "memory"
	CatIO        Category = "io"
	CatNet       Category = "net"
	CatHardware  Category = "hardware"
	CatLifecycle Category = "lifecycle"
	CatKernel    Category = "kernel"
)

type Kind string

const (
	KindEvent     Kind = "event"
	KindCondition Kind = "condition"
)

// Alert is one entry of the alert list. Fields are copied out of the engine,
// so callers may keep them.
type Alert struct {
	ID         uint64    `json:"id"`
	Key        string    `json:"key"`
	Rule       string    `json:"rule"`
	Kind       Kind      `json:"kind"`
	Severity   Severity  `json:"severity"`
	Category   Category  `json:"category"`
	DomainID   string    `json:"domain_id,omitempty"`
	DomainName string    `json:"domain,omitempty"`
	Subject    string    `json:"subject,omitempty"` // vcpu, device, interface...
	Message    string    `json:"message"`
	Value      float64   `json:"value,omitempty"`
	Source     string    `json:"source"` // ebpf | kmsg | metrics
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	Count      int       `json:"count"`
	Active     bool      `json:"active"`
	Resolved   time.Time `json:"resolved,omitzero"`
}

// Transition says why a subscriber is being notified.
type Transition string

const (
	Raised    Transition = "raised"
	Repeated  Transition = "repeated"
	Escalated Transition = "escalated" // severity of an active condition changed
	Cleared   Transition = "resolved"
)

// Sample is one observation of a condition, produced by a detector each
// tick for every subject it watches.
type Sample struct {
	Rule       string
	Category   Category
	DomainID   string
	DomainName string
	Subject    string
	Value      float64
	Level      config.Level
	LowerWorse bool // value below the thresholds is bad (free memory)
	// Format renders the message for a value at the given severity.
	Format func(v float64) string
}

func (s *Sample) key() string {
	return s.Rule + "|" + s.DomainID + "|" + s.Subject
}

// severity of v ignoring hysteresis; Info means "below warning".
func (s *Sample) severity(v float64) Severity {
	over := func(t float64) bool {
		if t == 0 {
			return false
		}
		if s.LowerWorse {
			return v <= t
		}
		return v >= t
	}
	switch {
	case over(s.Level.Crit):
		return Critical
	case over(s.Level.Warn):
		return Warning
	}
	return Info
}

// clear reports whether v is under the clear level, derived from the
// lowest enabled threshold.
func (s *Sample) clear(v float64, ratio float64) bool {
	t := s.Level.Warn
	if t == 0 {
		t = s.Level.Crit
	}
	if s.LowerWorse {
		return v > t/ratio
	}
	return v < t*ratio
}

type condState struct {
	pending     Severity // severity seen since pendingAt
	pendingAt   time.Time
	belowAt     time.Time // first time under the clear level, zero when not
	alert       *Alert    // non-nil while active
	lastSampled time.Time
}

type Engine struct {
	mu      sync.Mutex
	cfg     config.Alerts
	muted   map[string]bool
	nextID  uint64
	conds   map[string]*condState
	events  map[string]*Alert // event alerts by key, inside the dedup window
	history []*Alert          // events and resolved conditions, oldest first
	subs    []func(Alert, Transition)
	now     func() time.Time
}

func NewEngine(cfg config.Alerts) *Engine {
	e := &Engine{
		cfg:    cfg,
		muted:  make(map[string]bool),
		conds:  make(map[string]*condState),
		events: make(map[string]*Alert),
		now:    time.Now,
	}
	for _, r := range cfg.Mute {
		e.muted[r] = true
	}
	return e
}

// Subscribe registers fn for every transition. fn runs with the engine
// unlocked but must not block for long.
func (e *Engine) Subscribe(fn func(Alert, Transition)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.subs = append(e.subs, fn)
}

type notice struct {
	a Alert
	t Transition
}

func (e *Engine) notify(ns []notice) {
	e.mu.Lock()
	subs := slices.Clone(e.subs)
	e.mu.Unlock()
	for _, n := range ns {
		for _, fn := range subs {
			fn(n.a, n.t)
		}
	}
}

// Raise records an event alert. Key defaults to rule+domain+subject.
func (e *Engine) Raise(a Alert) {
	if e.muted[a.Rule] {
		return
	}
	now := e.now()
	if a.Last.IsZero() {
		a.Last = now
	}
	if a.Key == "" {
		a.Key = a.Rule + "|" + a.DomainID + "|" + a.Subject
	}
	e.mu.Lock()
	if old, ok := e.events[a.Key]; ok && a.Last.Sub(old.Last) < e.cfg.Dedup.Duration {
		old.Count++
		old.Last = a.Last
		old.Message = a.Message
		old.Value = a.Value
		if a.Severity > old.Severity {
			old.Severity = a.Severity
		}
		n := notice{*old, Repeated}
		e.mu.Unlock()
		e.notify([]notice{n})
		return
	}
	e.nextID++
	a.ID = e.nextID
	a.Kind = KindEvent
	a.First = a.Last
	a.Count = 1
	a.Active = false
	p := &a
	e.events[a.Key] = p
	e.pushHistory(p)
	n := notice{a, Raised}
	e.mu.Unlock()
	e.notify([]notice{n})
}

// Evaluate feeds one tick of condition samples. Conditions whose subject
// was not sampled (VM gone, metric unavailable) resolve immediately.
func (e *Engine) Evaluate(now time.Time, samples []Sample) {
	var ns []notice
	e.mu.Lock()
	for i := range samples {
		s := &samples[i]
		if e.muted[s.Rule] {
			continue
		}
		k := s.key()
		st := e.conds[k]
		if st == nil {
			st = &condState{}
			e.conds[k] = st
		}
		st.lastSampled = now
		if n, ok := e.step(st, s, k, now); ok {
			ns = append(ns, n)
		}
	}
	for k, st := range e.conds {
		if st.lastSampled.Equal(now) {
			continue
		}
		if st.alert != nil {
			ns = append(ns, e.resolve(st, now))
		}
		delete(e.conds, k)
	}
	e.expireEvents(now)
	e.mu.Unlock()
	e.notify(ns)
}

func (e *Engine) step(st *condState, s *Sample, key string, now time.Time) (notice, bool) {
	sev := s.severity(s.Value)
	if sev != st.pending {
		st.pending, st.pendingAt = sev, now
	}
	held := now.Sub(st.pendingAt) >= e.cfg.RaiseAfter.Duration

	if st.alert == nil {
		if sev == Info || !held {
			return notice{}, false
		}
		e.nextID++
		st.alert = &Alert{
			ID: e.nextID, Key: key, Rule: s.Rule, Kind: KindCondition,
			Severity: sev, Category: s.Category,
			DomainID: s.DomainID, DomainName: s.DomainName, Subject: s.Subject,
			Message: s.Format(s.Value), Value: s.Value, Source: "metrics",
			First: now, Last: now, Count: 1, Active: true,
		}
		st.belowAt = time.Time{}
		return notice{*st.alert, Raised}, true
	}

	a := st.alert
	a.Last, a.Value, a.DomainName = now, s.Value, s.DomainName
	if s.clear(s.Value, e.cfg.ClearRatio) {
		if st.belowAt.IsZero() {
			st.belowAt = now
		}
		if now.Sub(st.belowAt) >= e.cfg.ClearAfter.Duration {
			return e.resolve(st, now), true
		}
		return notice{}, false
	}
	st.belowAt = time.Time{}
	// Escalate as soon as it holds; de-escalate only from critical to
	// warning, never to "nothing" (that is what clearing is for).
	if sev != Info && sev != a.Severity && held {
		a.Severity = sev
		a.Message = s.Format(s.Value)
		return notice{*a, Escalated}, true
	}
	a.Message = s.Format(s.Value)
	return notice{}, false
}

func (e *Engine) resolve(st *condState, now time.Time) notice {
	a := st.alert
	a.Active = false
	a.Resolved = now
	st.alert = nil
	st.belowAt = time.Time{}
	e.pushHistory(a)
	return notice{*a, Cleared}
}

func (e *Engine) pushHistory(a *Alert) {
	e.history = append(e.history, a)
	if over := len(e.history) - e.cfg.History; over > 0 {
		e.history = slices.Delete(e.history, 0, over)
	}
}

func (e *Engine) expireEvents(now time.Time) {
	for k, a := range e.events {
		if now.Sub(a.Last) >= e.cfg.Dedup.Duration {
			delete(e.events, k)
		}
	}
}

// Active returns firing conditions, most severe first.
func (e *Engine) Active() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Alert
	for _, st := range e.conds {
		if st.alert != nil {
			out = append(out, *st.alert)
		}
	}
	sortAlerts(out)
	return out
}

// Recent returns the active conditions followed by up to n past alerts
// (events and resolved conditions), newest first. n <= 0 returns all.
func (e *Engine) Recent(n int) []Alert {
	out := e.Active()
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.history) - 1; i >= 0 && (n <= 0 || len(out) < n); i-- {
		out = append(out, *e.history[i])
	}
	return out
}

// DomainCounts returns, per domain, the number of active conditions plus
// the events seen within the dedup window, and the worst severity.
func (e *Engine) DomainCounts() map[string]DomainCount {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]DomainCount)
	add := func(a *Alert) {
		if a.DomainID == "" {
			return
		}
		c := out[a.DomainID]
		c.N++
		c.Worst = max(c.Worst, a.Severity)
		out[a.DomainID] = c
	}
	for _, st := range e.conds {
		if st.alert != nil {
			add(st.alert)
		}
	}
	for _, a := range e.events {
		if a.Severity > Info {
			add(a)
		}
	}
	return out
}

type DomainCount struct {
	N     int
	Worst Severity
}

func sortAlerts(as []Alert) {
	slices.SortFunc(as, func(a, b Alert) int {
		if a.Severity != b.Severity {
			return int(b.Severity) - int(a.Severity)
		}
		return b.First.Compare(a.First)
	})
}

func (a Alert) String() string {
	where := a.DomainName
	if a.Subject != "" {
		if where != "" {
			where += "/"
		}
		where += a.Subject
	}
	if where != "" {
		where = " [" + where + "]"
	}
	return fmt.Sprintf("%s %s%s: %s", a.Severity, a.Rule, where, a.Message)
}
