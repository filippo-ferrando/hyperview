//go:build !linux

package collect

import (
	"context"

	"hyperview/internal/store"
)

type EBPFCollector struct{}

func NewEBPFCollector() *EBPFCollector                                            { return &EBPFCollector{} }
func (ec *EBPFCollector) Name() string                                            { return "ebpf" }
func (ec *EBPFCollector) Close() error                                            { return nil }
func (ec *EBPFCollector) Collect(ctx context.Context, s *store.DomainStore) error { return nil }
