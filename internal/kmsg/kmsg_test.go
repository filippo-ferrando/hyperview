package kmsg

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	boot := time.Unix(1000, 0)
	r, ok := Parse("3,1234,5000000,-;I/O error, dev sda\\x2c sector 8\n SUBSYSTEM=block\n DEVICE=b8:0\n", boot)
	if !ok {
		t.Fatal("parse failed")
	}
	if r.Priority != 3 || r.Facility != 0 || r.Seq != 1234 {
		t.Errorf("header: %+v", r)
	}
	if !r.Time.Equal(boot.Add(5 * time.Second)) {
		t.Errorf("time %v", r.Time)
	}
	if r.Message != "I/O error, dev sda, sector 8" {
		t.Errorf("message %q", r.Message)
	}
	if r.Fields["SUBSYSTEM"] != "block" || r.Fields["DEVICE"] != "b8:0" {
		t.Errorf("fields %v", r.Fields)
	}
	if r, _ := Parse("14,1,1,-;hello", boot); r.Facility != 1 || r.Priority != 6 {
		t.Errorf("facility decoding: %+v", r)
	}
	if _, ok := Parse("garbage", boot); ok {
		t.Error("garbage parsed")
	}
}
