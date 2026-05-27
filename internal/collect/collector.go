package collect

import (
	"context"

	"hyperview/internal/store"
)

type Collector interface {
	Name() string
	Collect(ctx context.Context, store *store.DomainStore) error
	Close() error
}

type Registry struct {
	collectors []Collector
}

func NewRegistry() *Registry {
	return &Registry{
		collectors: make([]Collector, 0),
	}
}

func (r *Registry) Register(c Collector) {
	r.collectors = append(r.collectors, c)
}

func (r *Registry) Collectors() []Collector {
	return r.collectors
}
