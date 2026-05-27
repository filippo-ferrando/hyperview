package store

// RingBuffer holds the last N snapshots for sparkline rendering.
// Generic, thread-unsafe.
type RingBuffer[T any] struct {
	buf  []T
	pos  int
	size int
}

func NewRingBuffer[T any](size int) *RingBuffer[T] {
	return &RingBuffer[T]{
		buf:  make([]T, 0, size),
		size: size,
	}
}

func (r *RingBuffer[T]) Push(v T) {
	if len(r.buf) < r.size {
		r.buf = append(r.buf, v)
	} else {
		r.buf[r.pos] = v
		r.pos = (r.pos + 1) % r.size
	}
}

func (r *RingBuffer[T]) Slice() []T {
	if len(r.buf) < r.size {
		return r.buf
	}
	ret := make([]T, r.size)
	for i := 0; i < r.size; i++ {
		ret[i] = r.buf[(r.pos+i)%r.size]
	}
	return ret
}
