// Package bpf embeds the compiled hyperview eBPF object.
//
// The generated files are committed, so building hyperview only needs Go.
// Regenerating requires clang and libbpf headers: run `make bpf`.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -type event -type hist -type vm_counters -type vcpu_counters -type exit_key -type drop_key -type blk_key Hyperview src/hyperview.bpf.c -- -I./src
