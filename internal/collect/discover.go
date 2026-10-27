package collect

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KVMProcess is a host process that owns a KVM VM file descriptor.
type KVMProcess struct {
	PID     int
	Start   uint64 // starttime from /proc/<pid>/stat, guards against PID reuse
	Comm    string
	Source  string // qemu | firecracker | cloud-hypervisor | crosvm | kvmtool | kvm
	Name    string
	UUID    string
	MemMiB  uint64 // configured guest memory when parseable from the cmdline
	Taps    []string
	Cmdline []string
}

// ProcessIndex periodically scans /proc for processes holding an
// "anon_inode:kvm-vm" descriptor. That works for every KVM userspace,
// managed by libvirt or not. Reading other users' fds requires root.
type ProcessIndex struct {
	mu       sync.Mutex
	root     string
	interval time.Duration
	lastScan time.Time
	procs    map[int]*KVMProcess
}

func NewProcessIndex(interval time.Duration) *ProcessIndex {
	return &ProcessIndex{root: "/proc", interval: interval, procs: make(map[int]*KVMProcess)}
}

// Refresh rescans /proc when the scan interval has elapsed, otherwise it
// only drops processes that exited.
func (pi *ProcessIndex) Refresh(now time.Time) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	if now.Sub(pi.lastScan) < pi.interval {
		for pid, p := range pi.procs {
			if start, ok := pi.startTime(pid); !ok || start != p.Start {
				delete(pi.procs, pid)
			}
		}
		return
	}
	pi.lastScan = now
	pi.procs = pi.scan()
}

func (pi *ProcessIndex) All() []KVMProcess {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	out := make([]KVMProcess, 0, len(pi.procs))
	for _, p := range pi.procs {
		out = append(out, *p)
	}
	return out
}

func (pi *ProcessIndex) ByUUID(uuid string) (KVMProcess, bool) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	for _, p := range pi.procs {
		if p.UUID != "" && strings.EqualFold(p.UUID, uuid) {
			return *p, true
		}
	}
	return KVMProcess{}, false
}

func (pi *ProcessIndex) scan() map[int]*KVMProcess {
	out := make(map[int]*KVMProcess)
	entries, err := os.ReadDir(pi.root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if p := pi.inspect(pid); p != nil {
			out[pid] = p
		}
	}
	return out
}

func (pi *ProcessIndex) inspect(pid int) *KVMProcess {
	fdDir := filepath.Join(pi.root, strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	isVM := false
	var tunFDs []string
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			continue
		}
		switch target {
		case "anon_inode:kvm-vm":
			isVM = true
		case "/dev/net/tun":
			tunFDs = append(tunFDs, fd.Name())
		}
	}
	if !isVM {
		return nil
	}

	start, _ := pi.startTime(pid)
	p := &KVMProcess{PID: pid, Start: start}
	base := filepath.Join(pi.root, strconv.Itoa(pid))
	if b, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		p.Comm = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		p.Cmdline = strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	}
	for _, fd := range tunFDs {
		if tap := tapFromFdinfo(filepath.Join(base, "fdinfo", fd)); tap != "" {
			p.Taps = append(p.Taps, tap)
		}
	}
	parseHypervisorCmdline(p)
	return p
}

// startTime returns field 22 of /proc/<pid>/stat.
func (pi *ProcessIndex) startTime(pid int) (uint64, bool) {
	b, err := os.ReadFile(filepath.Join(pi.root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	// comm may contain spaces and parentheses: fields start after the last ')'.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	return v, err == nil
}

func tapFromFdinfo(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "iff:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseHypervisorCmdline fills Source, Name, UUID and MemMiB from argv.
func parseHypervisorCmdline(p *KVMProcess) {
	exe := ""
	if len(p.Cmdline) > 0 {
		exe = filepath.Base(p.Cmdline[0])
	}
	switch {
	case strings.HasPrefix(exe, "qemu") || strings.HasPrefix(p.Comm, "qemu") || p.Comm == "kvm":
		p.Source = "qemu"
	case strings.Contains(exe, "firecracker") || p.Comm == "firecracker":
		p.Source = "firecracker"
	case strings.Contains(exe, "cloud-hypervisor") || p.Comm == "cloud-hypervisor":
		p.Source = "cloud-hypervisor"
	case strings.Contains(exe, "crosvm") || p.Comm == "crosvm":
		p.Source = "crosvm"
	case exe == "lkvm" || p.Comm == "lkvm":
		p.Source = "kvmtool"
	default:
		p.Source = "kvm"
	}

	args := p.Cmdline
	arg := func(i int) string {
		if i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	for i, a := range args {
		switch a {
		case "-name":
			p.Name = qemuOpt(arg(i), "guest")
		case "-uuid":
			p.UUID = arg(i)
		case "-m":
			p.MemMiB = parseQemuMem(arg(i))
		case "--id", "-id":
			if p.Name == "" && p.Source == "firecracker" {
				p.Name = arg(i)
			}
		case "--name":
			if p.Name == "" {
				p.Name = arg(i)
			}
		}
	}
	if p.Name == "" {
		p.Name = p.Comm + "-" + strconv.Itoa(p.PID)
	}
}

// qemuOpt extracts key from a QEMU option string such as
// "guest=web01,debug-threads=on"; a bare leading value is returned as is.
func qemuOpt(s, key string) string {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		if v, ok := strings.CutPrefix(part, key+"="); ok {
			return v
		}
	}
	if len(parts) > 0 && !strings.Contains(parts[0], "=") {
		return parts[0]
	}
	return ""
}

// parseQemuMem parses "-m 4096", "-m 4G" or "-m size=4096M,slots=2" into MiB.
func parseQemuMem(s string) uint64 {
	v := qemuOpt(s, "size")
	if v == "" {
		return 0
	}
	mult := uint64(1)
	switch v[len(v)-1] {
	case 'G', 'g':
		mult, v = 1024, v[:len(v)-1]
	case 'T', 't':
		mult, v = 1024*1024, v[:len(v)-1]
	case 'M', 'm':
		v = v[:len(v)-1]
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0
	}
	return n * mult
}
