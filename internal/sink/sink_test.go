package sink

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperview/internal/alert"
)

func sampleAlert() alert.Alert {
	return alert.Alert{ID: 7, Rule: "vm.signal", Kind: alert.KindEvent, Severity: alert.Critical,
		Category: alert.CatLifecycle, DomainID: "id-1", DomainName: "web01", Subject: "tid 42",
		Message: "hypervisor received SIGSEGV (crash)", Source: "ebpf", Count: 1, Last: time.Unix(1000, 0)}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	j := NewJSON(&b)
	j.Write(sampleAlert(), alert.Raised)
	j.Write(sampleAlert(), alert.Repeated) // folded into the summary
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines: %s", len(lines), b.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"transition": "raised", "rule": "vm.signal", "severity": "critical", "domain": "web01", "count": 1.0} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
}

func TestJournalRecord(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "j.sock")
	srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	j, err := newJournal(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	a := sampleAlert()
	a.Message = "line one\nline two"
	j.Write(a, alert.Raised)

	buf := make([]byte, 8192)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	fields := parseJournal(t, buf[:n])
	if fields["PRIORITY"] != "2" || fields["HYPERVIEW_RULE"] != "vm.signal" || fields["HYPERVIEW_DOMAIN"] != "web01" {
		t.Errorf("fields %v", fields)
	}
	if !strings.Contains(fields["MESSAGE"], "line one\nline two") {
		t.Errorf("multi-line message lost: %q", fields["MESSAGE"])
	}
}

// parseJournal decodes the native journal protocol.
func parseJournal(t *testing.T, b []byte) map[string]string {
	out := map[string]string{}
	for len(b) > 0 {
		nl := bytes.IndexByte(b, '\n')
		line := b[:nl]
		if k, v, ok := bytes.Cut(line, []byte("=")); ok {
			out[string(k)] = string(v)
			b = b[nl+1:]
			continue
		}
		size := binary.LittleEndian.Uint64(b[nl+1:])
		out[string(line)] = string(b[nl+9 : nl+9+int(size)])
		b = b[nl+9+int(size)+1:]
	}
	return out
}

func TestJournalLevelHandler(t *testing.T) {
	var b bytes.Buffer
	l := slog.New(NewJournalLevelHandler(&b, nil)).With("k", "v")
	l.Warn("careful")
	l.Info("fine")
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "<4>") || !strings.HasPrefix(lines[1], "<6>") || !strings.Contains(lines[0], "k=v") {
		t.Fatalf("got %q", b.String())
	}
}
