#ifndef __VMLINUX_H__
#define __VMLINUX_H__

// Standard unsigned primitives
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

// Standard signed primitives (Required by host bpf_helper_defs.h)
typedef int __s32;
typedef long long __s64;

// Network byte-order primitives (Required by host bpf_helper_defs.h)
typedef unsigned short __be16;
typedef unsigned int __be32;
typedef unsigned int __wsum;

typedef int pid_t;

// Forward declarations for pointer references in system BPF helper wrappers
struct __sk_buff;
struct tcphdr;
struct iphdr;

struct trace_event_raw_kvm_exit {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  unsigned int exit_reason;
  __u64 vcpu_id;
  __u64 isa;
  __u64 info1;
  __u64 info2;
};

struct trace_event_raw_kvm_inj_virq {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  unsigned int irq;
  __u8 type;
  __u8 injected;
};

struct trace_event_raw_kvm_entry {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  __u64 vcpu_id;
};

struct trace_event_raw_kvm_mmu_page_fault {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  __u64 gva;
  __u32 error_code;
};

struct trace_event_raw_kvm_halt_poll_ns {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  __u8 grow;
  unsigned int vcpu_id;
  __u64 ns;
};

#endif /* __VMLINUX_H__ */
