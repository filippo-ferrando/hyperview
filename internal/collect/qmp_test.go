package collect

import (
	"strings"
	"testing"
)

func TestQMPSocket(t *testing.T) {
	cases := map[string]string{
		"qemu-system-x86_64 -qmp unix:/run/vm.qmp,server,nowait -m 1G": "/run/vm.qmp",
		"qemu-system-x86_64 -qmp unix:/run/vm.qmp,server=on,wait=off":  "/run/vm.qmp",
		"qemu-system-x86_64 -qmp unix:/run/vm.qmp":                     "",
		// Proxmox: a server-mode control monitor plus a client-mode event socket.
		"/usr/bin/kvm -id 100 -chardev socket,id=qmp,path=/var/run/qemu-server/100.qmp,server=on,wait=off " +
			"-mon chardev=qmp,mode=control -chardev socket,id=qmp-event,path=/var/run/qmeventd.sock,reconnect=5 " +
			"-mon chardev=qmp-event,mode=control": "/var/run/qemu-server/100.qmp",
		"qemu-system-x86_64 -chardev socket,id=m,path=/tmp/hmp,server=on -mon chardev=m": "",
	}
	for cmd, want := range cases {
		if got := qmpSocket(strings.Fields(cmd)); got != want {
			t.Errorf("%s:\n got %q want %q", cmd, got, want)
		}
	}
}

func TestQMPState(t *testing.T) {
	for in, want := range map[string][2]string{
		"running":        {"running", ""},
		"io-error":       {"paused", "io-error"},
		"guest-panicked": {"crashed", "guest-panicked"},
		"paused":         {"paused", "user"},
	} {
		s, r := qmpState(in)
		if s != want[0] || r != want[1] {
			t.Errorf("%s -> %s/%s", in, s, r)
		}
	}
}

func TestQMPBlockName(t *testing.T) {
	b := qmpBlockStats{QDev: "/machine/peripheral/virtio-disk0/virtio-backend"}
	if b.name() != "virtio-disk0" {
		t.Errorf("got %q", b.name())
	}
}
