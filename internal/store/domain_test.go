package store

import (
	"testing"
	"time"
)

func TestDomainStoreConcurrentUpdateAndSnapshot(t *testing.T) {
	store := NewDomainStore()

	snap := DomainSnapshot{
		ID:          "vm-uuid-111222",
		Name:        "ubuntu-production",
		State:       "running",
		CollectedAt: time.Now(),
	}

	store.Update(snap)

	got, exists := store.Get("vm-uuid-111222")
	if !exists {
		t.Fatalf("Expected snapshot to exist for ID 'vm-uuid-111222'")
	}
	if got.Name != "ubuntu-production" {
		t.Errorf("Expected name 'ubuntu-production', got '%s'", got.Name)
	}

	snaps := store.Snapshot()
	if len(snaps) != 1 {
		t.Errorf("Expected snapshot list count to be 1, got %d", len(snaps))
	}
}
