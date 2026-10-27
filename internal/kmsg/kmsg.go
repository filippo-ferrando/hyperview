// Package kmsg follows the kernel log through /dev/kmsg.
package kmsg

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Record is one kernel log record.
type Record struct {
	Priority int // syslog level 0 (emerg) .. 7 (debug)
	Facility int
	Seq      uint64
	Time     time.Time
	Message  string
	Fields   map[string]string // continuation key=value lines (SUBSYSTEM, DEVICE)
}

// Reader follows /dev/kmsg. Reading it requires CAP_SYSLOG when
// kernel.dmesg_restrict=1, the default on most distributions.
type Reader struct {
	f    *os.File
	boot time.Time
}

func Open() (*Reader, error) {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/kmsg: %w", err)
	}
	// A non-blocking fd lets the runtime poller park reads, so Close
	// unblocks a pending Read.
	return &Reader{f: os.NewFile(uintptr(fd), "/dev/kmsg"), boot: bootTime()}, nil
}

func (r *Reader) Close() error { return r.f.Close() }

// Next returns the next record, blocking until one is logged. Records lost
// to ring buffer overruns are skipped.
func (r *Reader) Next() (Record, error) {
	buf := make([]byte, 8192)
	for {
		n, err := r.f.Read(buf)
		if err != nil {
			if errors.Is(err, syscall.EPIPE) { // overrun: next read resumes at the oldest record
				continue
			}
			if errors.Is(err, syscall.EINVAL) { // record larger than buf, cannot happen with 8K
				continue
			}
			return Record{}, err
		}
		rec, ok := Parse(string(buf[:n]), r.boot)
		if ok {
			return rec, nil
		}
	}
}

// Parse decodes one /dev/kmsg record: "prio,seq,usec,flags;message\n"
// followed by optional " KEY=value" lines.
func Parse(s string, boot time.Time) (Record, bool) {
	head, rest, ok := strings.Cut(s, ";")
	if !ok {
		return Record{}, false
	}
	parts := strings.Split(head, ",")
	if len(parts) < 3 {
		return Record{}, false
	}
	prio, err1 := strconv.Atoi(parts[0])
	seq, err2 := strconv.ParseUint(parts[1], 10, 64)
	usec, err3 := strconv.ParseUint(parts[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return Record{}, false
	}
	lines := strings.Split(strings.TrimRight(rest, "\n"), "\n")
	rec := Record{
		Priority: prio & 7,
		Facility: prio >> 3,
		Seq:      seq,
		Time:     boot.Add(time.Duration(usec) * time.Microsecond),
		Message:  unescape(lines[0]),
	}
	for _, l := range lines[1:] {
		if k, v, ok := strings.Cut(strings.TrimPrefix(l, " "), "="); ok {
			if rec.Fields == nil {
				rec.Fields = make(map[string]string)
			}
			rec.Fields[k] = v
		}
	}
	return rec, true
}

// unescape decodes the \xNN escapes the kernel uses for non-printable bytes.
func unescape(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// bootTime estimates the wall time of boot for the monotonic clock the
// kernel log uses.
func bootTime() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(ts.Nano()))
}
