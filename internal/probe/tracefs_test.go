package probe

import (
	"strings"
	"testing"
)

const kvmExitFormat = `name: kvm_exit
ID: 1885
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned int exit_reason;	offset:8;	size:4;	signed:0;
	field:unsigned long guest_rip;	offset:16;	size:8;	signed:0;
	field:u8 insn[15];	offset:24;	size:15;	signed:0;

print fmt: "reason %s"
`

func TestParseFormat(t *testing.T) {
	f, err := parseFormat(strings.NewReader(kvmExitFormat))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Field{
		"exit_reason": {"exit_reason", 8, 4},
		"guest_rip":   {"guest_rip", 16, 8},
		"insn":        {"insn", 24, 15},
		"common_pid":  {"common_pid", 4, 4},
	}
	for name, w := range want {
		if got := f[name]; got != w {
			t.Errorf("%s: got %+v want %+v", name, got, w)
		}
	}
}
