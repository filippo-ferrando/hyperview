package store

import (
	"reflect"
	"testing"
)

func TestRingBuffer(t *testing.T) {
	rb := NewRingBuffer[int](3)
	if len(rb.Slice()) != 0 {
		t.Errorf("Expected empty slice on initialization, got %v", rb.Slice())
	}

	rb.Push(10)
	rb.Push(20)
	if !reflect.DeepEqual(rb.Slice(), []int{10, 20}) {
		t.Errorf("Expected partial array [10 20], got %v", rb.Slice())
	}

	rb.Push(30)
	if !reflect.DeepEqual(rb.Slice(), []int{10, 20, 30}) {
		t.Errorf("Expected full array [10 20 30], got %v", rb.Slice())
	}

	// Overwrite ring behavior
	rb.Push(40)
	if !reflect.DeepEqual(rb.Slice(), []int{20, 30, 40}) {
		t.Errorf("Expected FIFO wrap around [20 30 40], got %v", rb.Slice())
	}
}
