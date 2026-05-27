package collect

import (
	"context"

	"hyperview/internal/store"
)

type MockCollector struct{}

func NewMockCollector() *MockCollector {
	return &MockCollector{}
}

func (m *MockCollector) Name() string {
	return "mock_collector"
}

func (m *MockCollector) Collect(ctx context.Context, s *store.DomainStore) error {
	return nil
}

func (m *MockCollector) Close() error {
	return nil
}
