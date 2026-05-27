// internal/bpf/_kvm_events.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0

struct vcpu_metrics {
  __u64 exit_count;
  __u64 last_exit_ts;
  __u64 total_wait_ns;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 512);
  __type(key, __u32);   // exit_reason
  __type(value, __u64); // count
} exit_counts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32);  // tgid (QEMU main process pid)
  __type(value, __u8); // 1 = monitored
} target_pids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // tid (vCPU host thread id)
  __type(value, struct vcpu_metrics);
} vcpu_stats SEC(".maps");

SEC("raw_tracepoint/kvm_exit")
int handle_kvm_exit(struct bpf_raw_tracepoint_args *ctx) {
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  __u32 tid = (__u32)bpf_get_current_pid_tgid();

  if (!bpf_map_lookup_elem(&target_pids, &tgid))
    return 0;

  // exit_reason!
  __u32 exit_reason = (__u32)ctx->args[2];

  // Aggregate real exit counters atomically into the global histogram map
  __u64 one = 1, *cnt;
  cnt = bpf_map_lookup_elem(&exit_counts, &exit_reason);
  if (cnt) {
    __sync_fetch_and_add(cnt, 1);
  } else {
    bpf_map_update_elem(&exit_counts, &exit_reason, &one, BPF_ANY);
  }

  // Log exit event times for this specific vCPU thread context
  struct vcpu_metrics *m = bpf_map_lookup_elem(&vcpu_stats, &tid);
  if (m) {
    m->exit_count++;
    m->last_exit_ts = bpf_ktime_get_ns();
  } else {
    struct vcpu_metrics new_m = {.exit_count = 1,
                                 .last_exit_ts = bpf_ktime_get_ns(),
                                 .total_wait_ns = 0};
    bpf_map_update_elem(&vcpu_stats, &tid, &new_m, BPF_ANY);
  }
  return 0;
}

SEC("raw_tracepoint/kvm_entry")
int handle_kvm_entry(struct bpf_raw_tracepoint_args *ctx) {
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  __u32 tid = (__u32)bpf_get_current_pid_tgid();

  if (!bpf_map_lookup_elem(&target_pids, &tgid))
    return 0;

  // Compute real scheduling latency (time spent waiting in host kernel context)
  struct vcpu_metrics *m = bpf_map_lookup_elem(&vcpu_stats, &tid);
  if (m && m->last_exit_ts > 0) {
    __u64 delta = bpf_ktime_get_ns() - m->last_exit_ts;
    m->total_wait_ns += delta;
    m->last_exit_ts = 0;
  }
  return 0;
}

SEC("raw_tracepoint/kvm_inj_virq")
int handle_kvm_inj_virq(struct bpf_raw_tracepoint_args *ctx) { return 0; }
SEC("raw_tracepoint/kvm_mmu_page_fault")
int handle_kvm_mmu_page_fault(struct bpf_raw_tracepoint_args *ctx) { return 0; }
SEC("kprobe/handle_mm_fault")
int handle_mm_fault_kprobe(void *ctx) { return 0; }
SEC("raw_tracepoint/kvm_dirty_ring_push")
int handle_kvm_dirty_ring_push(struct bpf_raw_tracepoint_args *ctx) {
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
