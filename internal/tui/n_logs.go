package tui

import (
	"sync"
)

type LogRingBuffer struct {
	mu    sync.RWMutex
	lines []string
	max   int
}

var GlobalLogRing = LogRingBuffer{
	lines: make([]string, 0, 50),
	max:   50,
}

func (lr *LogRingBuffer) Write(p []byte) (n int, err error) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	cleanedLine := string(p)
	if len(lr.lines) >= lr.max {
		lr.lines = lr.lines[1:]
	}
	lr.lines = append(lr.lines, cleanedLine)
	return len(p), nil
}

func (lr *LogRingBuffer) GetTail(n int) []string {
	lr.mu.RLock()
	defer lr.mu.RUnlock()

	total := len(lr.lines)
	if total == 0 {
		return []string{"[No logs registered yet]"}
	}

	start := total - n
	if start < 0 {
		start = 0
	}

	result := make([]string, total-start)
	copy(result, lr.lines[start:])
	return result
}
