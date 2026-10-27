package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseHypervisorCmdline(t *testing.T) {
	cases := []struct {
		cmdline string
		source  string
		name    string
		uuid    string
		mem     uint64
	}{
		{"/usr/bin/qemu-system-x86_64\x00-name\x00guest=web01,debug-threads=on\x00-uuid\x00f0e1d2c3-0000-4000-8000-000000000001\x00-m\x00size=4194304k\x00", "qemu", "web01", "f0e1d2c3-0000-4000-8000-000000000001", 0},
		{"/usr/bin/kvm\x00-id\x00101\x00-name\x00db01,debug-threads=on\x00-m\x004096\x00", "qemu", "db01", "", 4096},
		{"/usr/bin/qemu-system-aarch64\x00-m\x002G\x00", "qemu", "qemu-system-aar-42", "", 2048},
		{"/opt/firecracker\x00--id\x00fc-7\x00", "firecracker", "fc-7", "", 0},
		{"/usr/bin/cloud-hypervisor\x00--kernel\x00vmlinux\x00", "cloud-hypervisor", "cloud-hyperviso-42", "", 0},
	}
	for _, c := range cases {
		args := strings.Split(strings.TrimRight(c.cmdline, "\x00"), "\x00")
		comm := filepath.Base(args[0])
		if len(comm) > 15 {
			comm = comm[:15]
		}
		p := &KVMProcess{PID: 42, Comm: comm, Cmdline: args}
		parseHypervisorCmdline(p)
		if p.Source != c.source || p.Name != c.name || p.UUID != c.uuid || p.MemMiB != c.mem {
			t.Errorf("%q: got source=%q name=%q uuid=%q mem=%d", args[0], p.Source, p.Name, p.UUID, p.MemMiB)
		}
	}
}

func TestVCPUIndex(t *testing.T) {
	for comm, want := range map[string]int{"CPU 3/KVM": 3, "fc_vcpu 1": 1, "vcpu12": 12, "kvm-vcpu-0": 0, "crosvm_vcpu5": 5} {
		if got, ok := vcpuIndex(comm); !ok || got != want {
			t.Errorf("%q: got %d,%v want %d", comm, got, ok, want)
		}
	}
	for _, comm := range []string{"IO mon_iothread", "qemu-system-x86", "CPU x/KVM"} {
		if _, ok := vcpuIndex(comm); ok {
			t.Errorf("%q should not be a vCPU thread", comm)
		}
	}
}

func TestProcessIndexScan(t *testing.T) {
	root := t.TempDir()
	mk := func(pid, comm, cmdline string, fds map[string]string) {
		dir := filepath.Join(root, pid)
		for _, sub := range []string{"fd", "fdinfo"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644)
		os.WriteFile(filepath.Join(dir, "stat"), []byte(pid+" ("+comm+") S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0"), 0o644)
		for fd, target := range fds {
			os.Symlink(target, filepath.Join(dir, "fd", fd))
		}
	}
	mk("100", "qemu-system-x86", "qemu-system-x86_64\x00-name\x00vm1\x00", map[string]string{
		"3": "/dev/kvm", "4": "anon_inode:kvm-vm", "5": "/dev/net/tun",
	})
	os.WriteFile(filepath.Join(root, "100", "fdinfo", "5"), []byte("pos:\t0\nflags:\t02\niff:\ttap7\n"), 0o644)
	mk("200", "bash", "bash\x00", map[string]string{"0": "/dev/pts/1"})

	pi := NewProcessIndex(time.Minute)
	pi.root = root
	pi.Refresh(time.Now())

	all := pi.All()
	if len(all) != 1 {
		t.Fatalf("want 1 KVM process, got %d", len(all))
	}
	p := all[0]
	if p.PID != 100 || p.Name != "vm1" || p.Start != 12345 || len(p.Taps) != 1 || p.Taps[0] != "tap7" {
		t.Fatalf("unexpected process: %+v", p)
	}

	os.RemoveAll(filepath.Join(root, "100"))
	pi.Refresh(time.Now())
	if len(pi.All()) != 0 {
		t.Fatal("exited process should be dropped between scans")
	}
}
