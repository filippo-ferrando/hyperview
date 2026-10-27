// Package sink writes alert transitions for headless operation: native
// journald records when running under systemd, JSON lines otherwise.
package sink

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"hyperview/internal/alert"
)

// Sink receives alert transitions; it is an alert.Engine subscriber.
type Sink interface {
	Write(a alert.Alert, t alert.Transition)
}

// Emitted reports whether a transition is written by headless sinks;
// repeats are folded into the summary emitted when the dedup window closes.
func Emitted(t alert.Transition) bool { return t != alert.Repeated }

// Record is the JSON form of a transition.
type Record struct {
	Time       time.Time `json:"time"`
	Transition string    `json:"transition"`
	alert.Alert
}

// JSON writes one JSON object per line.
type JSON struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewJSON(w io.Writer) *JSON { return &JSON{enc: json.NewEncoder(w)} }

func (j *JSON) Write(a alert.Alert, t alert.Transition) {
	if !Emitted(t) {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.enc.Encode(Record{Time: time.Now(), Transition: string(t), Alert: a})
}

const journalSocket = "/run/systemd/journal/socket"

// Journal sends structured records to systemd-journald.
type Journal struct {
	mu   sync.Mutex
	conn *net.UnixConn
	addr *net.UnixAddr
}

// UnderJournald reports whether stdout or stderr is connected to the journal,
// following the JOURNAL_STREAM protocol of systemd.exec(5).
func UnderJournald() bool {
	dev, ino, ok := strings.Cut(os.Getenv("JOURNAL_STREAM"), ":")
	if !ok {
		return false
	}
	for _, f := range []*os.File{os.Stderr, os.Stdout} {
		var st syscall.Stat_t
		if syscall.Fstat(int(f.Fd()), &st) == nil &&
			fmt.Sprint(st.Dev) == dev && fmt.Sprint(st.Ino) == ino {
			return true
		}
	}
	return false
}

func NewJournal() (*Journal, error) { return newJournal(journalSocket) }

func newJournal(socket string) (*Journal, error) {
	addr := &net.UnixAddr{Name: socket, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	return &Journal{conn: conn, addr: addr}, nil
}

// priority maps a transition to a syslog priority.
func priority(a alert.Alert, t alert.Transition) int {
	if t == alert.Cleared {
		return 5 // notice
	}
	switch a.Severity {
	case alert.Critical:
		return 2
	case alert.Warning:
		return 4
	}
	return 6
}

func (j *Journal) Write(a alert.Alert, t alert.Transition) {
	if !Emitted(t) {
		return
	}
	msg := fmt.Sprintf("%s: %s", t, a.String())
	if a.Count > 1 {
		msg += fmt.Sprintf(" (×%d)", a.Count)
	}
	fields := [][2]string{
		{"MESSAGE", msg},
		{"PRIORITY", fmt.Sprint(priority(a, t))},
		{"SYSLOG_IDENTIFIER", "hyperview"},
		{"HYPERVIEW_TRANSITION", string(t)},
		{"HYPERVIEW_ALERT_ID", fmt.Sprint(a.ID)},
		{"HYPERVIEW_RULE", a.Rule},
		{"HYPERVIEW_SEVERITY", a.Severity.String()},
		{"HYPERVIEW_CATEGORY", string(a.Category)},
		{"HYPERVIEW_KIND", string(a.Kind)},
		{"HYPERVIEW_SOURCE", a.Source},
		{"HYPERVIEW_COUNT", fmt.Sprint(a.Count)},
	}
	for _, f := range [][2]string{{"HYPERVIEW_DOMAIN", a.DomainName}, {"HYPERVIEW_DOMAIN_ID", a.DomainID}, {"HYPERVIEW_SUBJECT", a.Subject}} {
		if f[1] != "" {
			fields = append(fields, f)
		}
	}
	if a.Kind == alert.KindCondition {
		fields = append(fields, [2]string{"HYPERVIEW_VALUE", fmt.Sprint(a.Value)})
	}

	var b bytes.Buffer
	for _, f := range fields {
		if strings.ContainsRune(f[1], '\n') {
			// Binary-safe form: NAME\n<le64 length>value\n
			b.WriteString(f[0])
			b.WriteByte('\n')
			binary.Write(&b, binary.LittleEndian, uint64(len(f[1])))
			b.WriteString(f[1])
			b.WriteByte('\n')
			continue
		}
		b.WriteString(f[0] + "=" + f[1] + "\n")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.conn.WriteToUnix(b.Bytes(), j.addr); err != nil {
		fmt.Fprintf(os.Stderr, "hyperview: journal write failed: %v: %s\n", err, msg)
	}
}

func (j *Journal) Close() error { return j.conn.Close() }

// JournalLevelHandler prefixes each log line with its syslog priority
// ("<4>"), which journald reads from a service's stderr.
type JournalLevelHandler struct {
	mu  *sync.Mutex
	w   io.Writer
	buf *bytes.Buffer
	h   slog.Handler
}

func NewJournalLevelHandler(w io.Writer, opts *slog.HandlerOptions) *JournalLevelHandler {
	buf := &bytes.Buffer{}
	return &JournalLevelHandler{mu: &sync.Mutex{}, w: w, buf: buf, h: slog.NewTextHandler(buf, opts)}
}

func (j *JournalLevelHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return j.h.Enabled(ctx, l)
}

func (j *JournalLevelHandler) Handle(ctx context.Context, r slog.Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.buf.Reset()
	prio := 6
	switch {
	case r.Level >= slog.LevelError:
		prio = 3
	case r.Level >= slog.LevelWarn:
		prio = 4
	case r.Level < slog.LevelInfo:
		prio = 7
	}
	fmt.Fprintf(j.buf, "<%d>", prio)
	if err := j.h.Handle(ctx, r); err != nil {
		return err
	}
	_, err := j.w.Write(j.buf.Bytes())
	return err
}

func (j *JournalLevelHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &JournalLevelHandler{mu: j.mu, w: j.w, buf: j.buf, h: j.h.WithAttrs(as)}
}

func (j *JournalLevelHandler) WithGroup(name string) slog.Handler {
	return &JournalLevelHandler{mu: j.mu, w: j.w, buf: j.buf, h: j.h.WithGroup(name)}
}
