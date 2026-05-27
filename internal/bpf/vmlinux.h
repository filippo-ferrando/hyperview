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

struct __sk_buff;
struct tcphdr;
struct iphdr;

struct bpf_raw_tracepoint_args {
  __u64 args[0];
};

// restored layout definition for standard tracepoint context parsing
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
} __attribute__((preserve_access_index));

// restored layout definition for standard tracepoint context parsing
struct trace_event_raw_kvm_entry {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  __u64 vcpu_id;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
