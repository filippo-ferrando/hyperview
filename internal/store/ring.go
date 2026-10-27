package store

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

// Slice returns a copy of the contents, oldest first.
func (r *RingBuffer[T]) Slice() []T {
	ret := make([]T, len(r.buf))
	if len(r.buf) < r.size {
		copy(ret, r.buf)
		return ret
	}
	for i := 0; i < r.size; i++ {
		ret[i] = r.buf[(r.pos+i)%r.size]
	}
	return ret
}
