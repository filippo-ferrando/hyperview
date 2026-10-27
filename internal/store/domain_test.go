package store

import (
	"testing"
	"time"
)

func TestDomainStoreUpsertRetainCommit(t *testing.T) {
	s := NewDomainStore()

	s.Upsert("a", func(d *DomainSnapshot) {
		d.Name = "alpha"
		d.State = "running"
		d.VCPUs = []VCPUStat{{Index: 0, CPUPercent: 40}, {Index: 1, CPUPercent: 10}}
	})
	s.Upsert("b", func(d *DomainSnapshot) { d.Name = "beta" })

	if !s.Mutate("a", func(d *DomainSnapshot) { d.Mem.RssKiB = 1024 }) {
		t.Fatal("Mutate on existing domain should succeed")
	}
	if s.Mutate("missing", func(d *DomainSnapshot) {}) {
		t.Fatal("Mutate on unknown domain should be a no-op")
	}

	s.Commit(time.Now())
	s.Commit(time.Now())

	got, ok := s.Get("a")
	if !ok || got.Name != "alpha" || got.Mem.RssKiB != 1024 {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	if h := s.History("a"); len(h.CPU) != 2 || h.CPU[0] != 50 {
		t.Fatalf("want two CPU samples of 50%%, got %v", h.CPU)
	}

	// Snapshots must be deep copies.
	got.VCPUs[0].CPUPercent = 99
	if again, _ := s.Get("a"); again.VCPUs[0].CPUPercent != 40 {
		t.Fatal("snapshot aliases store memory")
	}

	removed := s.Retain(map[DomainID]bool{"a": true})
	if len(removed) != 1 || removed[0] != "b" {
		t.Fatalf("want b removed, got %v", removed)
	}
	if snaps := s.Snapshot(); len(snaps) != 1 {
		t.Fatalf("want 1 domain left, got %d", len(snaps))
	}
}
