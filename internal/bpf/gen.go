package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel KvmEvents _kvm_events.c -- -I. -O2 -g
