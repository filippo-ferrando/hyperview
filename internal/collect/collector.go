package collect

import (
	"context"
	"log/slog"
	"time"

	"hyperview/internal/store"
)

type Collector interface {
	Name() string
	Collect(ctx context.Context, store *store.DomainStore) error
	Close() error
}

// Discoverer is a Collector that owns domains. After Collect, Alive lists
// the domains it currently knows about; domains no discoverer reports are
// pruned from the store.
type Discoverer interface {
	Collector
	Alive() []store.DomainID
}

// Poller runs all collectors once per tick: discoverers first, then the
// remaining collectors, then the store commit.
type Poller struct {
	store       *store.DomainStore
	discoverers []Discoverer
	collectors  []Collector
	lastAlive   map[string][]store.DomainID
	afterTick   []func(time.Time)
}

func NewPoller(s *store.DomainStore) *Poller {
	return &Poller{store: s, lastAlive: make(map[string][]store.DomainID)}
}

// Register adds a collector; Discoverers are detected automatically.
func (p *Poller) Register(c Collector) {
	if d, ok := c.(Discoverer); ok {
		p.discoverers = append(p.discoverers, d)
		return
	}
	p.collectors = append(p.collectors, c)
}

// AfterTick registers a hook run after every committed tick.
func (p *Poller) AfterTick(fn func(time.Time)) { p.afterTick = append(p.afterTick, fn) }

func (p *Poller) Tick(ctx context.Context) {
	alive := make(map[store.DomainID]bool)
	for _, d := range p.discoverers {
		if err := d.Collect(ctx, p.store); err != nil {
			slog.Debug("discovery failed", slog.String("collector", d.Name()), slog.Any("err", err))
		} else {
			p.lastAlive[d.Name()] = d.Alive()
		}
		// Keep the last good result on transient errors to avoid flapping.
		for _, id := range p.lastAlive[d.Name()] {
			alive[id] = true
		}
	}
	for _, id := range p.store.Retain(alive) {
		slog.Info("domain gone", slog.String("id", id))
	}

	for _, c := range p.collectors {
		if err := c.Collect(ctx, p.store); err != nil {
			slog.Debug("collection failed", slog.String("collector", c.Name()), slog.Any("err", err))
		}
	}

	now := time.Now()
	p.store.Commit(now)
	for _, fn := range p.afterTick {
		fn(now)
	}
}

// Run ticks every interval until ctx is cancelled.
func (p *Poller) Run(ctx context.Context, interval time.Duration) {
	p.Tick(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Tick(ctx)
		}
	}
}

func (p *Poller) Close() {
	for _, d := range p.discoverers {
		_ = d.Close()
	}
	for _, c := range p.collectors {
		_ = c.Close()
	}
}
