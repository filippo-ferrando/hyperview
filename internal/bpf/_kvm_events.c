#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_PERCPU_HASH 6
#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} kvm_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 512);
  __type(key, __u32);   // exit_reason
  __type(value, __u64); // count
} exit_counts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32);  // tgid (QEMU pid)
  __type(value, __u8); // 1 = monitored
} target_pids SEC(".maps");

struct kvm_exit_event {
  __u32 pid;
  __u32 vcpu_id;
  __u32 exit_reason;
  __u64 timestamp_ns;
};

SEC("tp/kvm/kvm_exit")
int handle_kvm_exit(struct trace_event_raw_kvm_exit *ctx) {
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  if (!bpf_map_lookup_elem(&target_pids, &tgid))
    return 0;

  struct kvm_exit_event *e = bpf_ringbuf_reserve(&kvm_events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = tgid;
  e->vcpu_id = ctx->vcpu_id;
  e->exit_reason = ctx->exit_reason;
  e->timestamp_ns = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);

  __u64 one = 1, *cnt;
  cnt = bpf_map_lookup_elem(&exit_counts, &ctx->exit_reason);
  if (cnt) {
    __sync_fetch_and_add(cnt, 1);
  } else {
    bpf_map_update_elem(&exit_counts, &ctx->exit_reason, &one, BPF_ANY);
  }
  return 0;
}

SEC("tp/kvm/kvm_inj_virq")
int handle_kvm_inj_virq(struct trace_event_raw_kvm_inj_virq *ctx) {
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  if (!bpf_map_lookup_elem(&target_pids, &tgid))
    return 0;

  return 0;
}

SEC("tp/kvm/kvm_mmu_page_fault")
int handle_kvm_mmu_page_fault(struct trace_event_raw_kvm_mmu_page_fault *ctx) {
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  if (!bpf_map_lookup_elem(&target_pids, &tgid))
    return 0;

  return 0;
}

SEC("tp/kvm/kvm_halt_poll_ns")
int handle_kvm_halt_poll_ns(struct trace_event_raw_kvm_halt_poll_ns *ctx) {
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  if (!bpf_map_lookup_elem(&target_pids, &tgid))
    return 0;

  return 0;
}

SEC("kprobe/handle_mm_fault")
int handle_mm_fault_kprobe(void *ctx) {
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  if (!bpf_map_lookup_elem(&target_pids, &tgid))
    return 0;

  return 0;
}

SEC("tp/kvm/kvm_dirty_ring_push")
int handle_kvm_dirty_ring_push(void *ctx) {
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;
  if (!bpf_map_lookup_elem(&target_pids, &tgid))
    return 0;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
