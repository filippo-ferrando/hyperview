package bpf

import (
	_ "embed"

	"github.com/cilium/ebpf"
)

type KvmEventsObjects struct {
	KvmEventsPrograms
	KvmEventsMaps
}

type KvmEventsPrograms struct {
	HandleKvmExit    *ebpf.Program `ebpf:"handle_kvm_exit"`
	HandleKvmInjVirq *ebpf.Program `ebpf:"handle_kvm_inj_virq"`
}

type KvmEventsMaps struct {
	KvmEvents  *ebpf.Map `ebpf:"kvm_events"`
	ExitCounts *ebpf.Map `ebpf:"exit_counts"`
	TargetPids *ebpf.Map `ebpf:"target_pids"`
}

func (o *KvmEventsObjects) Close() error {
	closers := []interface{ Close() error }{
		o.HandleKvmExit, o.HandleKvmInjVirq,
		o.KvmEvents, o.ExitCounts, o.TargetPids,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

func LoadKvmEventsObjects(obj *KvmEventsObjects, opts *ebpf.CollectionOptions) error {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"kvm_events":  {Type: ebpf.RingBuf, MaxEntries: 256 * 1024},
			"exit_counts": {Type: ebpf.PerCPUHash, KeySize: 4, ValueSize: 8, MaxEntries: 512},
			"target_pids": {Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 256},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"handle_kvm_exit":     {Type: ebpf.TracePoint, License: "GPL"},
			"handle_kvm_inj_virq": {Type: ebpf.TracePoint, License: "GPL"},
		},
	}
	return spec.LoadAndAssign(obj, opts)
}
