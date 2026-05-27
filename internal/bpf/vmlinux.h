#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef int pid_t;

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

#endif /* __VMLINUX_H__ */
