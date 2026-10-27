// SPDX-License-Identifier: GPL-2.0
/* hyperview kernel probes.
 *
 * Classic tracepoints (kvm, block, oom, mce) read their fields at offsets
 * taken from tracefs "format" files by the loader, so they need neither
 * kernel module BTF nor struct layouts that change between versions.
 * BTF tracepoints (sched, signal, skb) use CO-RE relocations.
 *
 * Counters are cumulative; userspace turns them into rates and windows.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_TARGETS 1024
#define HIST_SLOTS 27 /* log2 microseconds, up to ~67s */
#define EVENT_GAP_NS 100000000ULL /* at most one event per (tgid,type) per 100ms */

#define TASK_RUNNING 0

/* Field offsets of classic tracepoints, set by the loader. */
volatile const __u32 off_kvm_exit_reason = 0;
volatile const __u32 off_kvm_exit_reason2 = 0; /* arm64 "ret"; 0 when absent */
volatile const __u32 off_uexit_reason = 0;
volatile const __u32 off_uexit_errno = 0;
volatile const __u32 off_emul_rip = 0;
volatile const __u32 off_emul_failed = 0;
volatile const __u32 off_exc_vector = 0;
volatile const __u32 off_exc_errcode = 0;
volatile const __u32 off_wake_ns = 0;
volatile const __u32 off_wake_waited = 0;
volatile const __u32 off_rqi_dev = 0;
volatile const __u32 off_rqi_sector = 0;
volatile const __u32 off_rqi_nr = 0;
volatile const __u32 off_rqc_dev = 0;
volatile const __u32 off_rqc_sector = 0;
volatile const __u32 off_rqc_nr = 0;
volatile const __u32 off_rqc_error = 0;
volatile const __u32 off_oom_pid = 0;
volatile const __u32 off_mce_status = 0;
volatile const __u32 off_mce_addr = 0;
volatile const __u32 off_mce_bank = 0;
volatile const __u32 off_mce_mcgstatus = 0;

#define TP_READ(dst, off) bpf_probe_read_kernel(&(dst), sizeof(dst), (void *)ctx + (off))

enum event_type {
	EV_KVM_UEXIT = 1,  /* a: KVM_EXIT_* reason, b: errno */
	EV_KVM_EMUL_FAIL,  /* a: guest rip */
	EV_KVM_EXCEPTION,  /* a: vector, b: error code */
	EV_OOM_VICTIM,     /* tgid: victim */
	EV_SIGNAL,         /* a: signal, b: sender tgid, comm: sender */
	EV_EXIT,           /* a: exit_code */
	EV_BLK_ERROR,      /* a: dev, b: sector, c: error, d: sectors */
	EV_MCE,            /* a: status, b: addr, c: bank, d: mcgstatus */
};

struct event {
	__u64 ts;
	__u32 type;
	__u32 tgid;
	__u32 tid;
	__u32 cpu;
	__s64 a;
	__s64 b;
	__s64 c;
	__s64 d;
	char comm[16];
};

struct exit_key {
	__u32 tgid;
	__u32 reason;
};

struct vm_counters {
	__u64 irq_injections;
	__u64 exceptions;
	__u64 emul_failures;
	__u64 halt_polls_ok; /* halts resolved by polling */
	__u64 halt_waits;    /* halts that had to sleep */
	__u64 halt_wait_ns;
};

struct vcpu_counters {
	__u64 exits;
	__u64 halt_waits;
};

struct hist {
	__u64 slots[HIST_SLOTS];
	__u64 count;
	__u64 sum_us;
	__u64 max_us;
};

struct blk_key {
	__u32 dev;
	__u32 pad;
	__u64 sector;
};

struct blk_start {
	__u64 ts;
	__u32 tgid;
	__u32 pad;
};

struct drop_key {
	__u32 ifindex;
	__u32 reason;
};

struct rl_key {
	__u32 tgid;
	__u32 type;
};

/* struct event only travels through the ring buffer; this keeps it in BTF
 * so bpf2go can generate the matching Go type. */
const struct event *unused_event __attribute__((unused));


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TARGETS);
	__type(key, __u32); /* hypervisor tgid */
	__type(value, __u32);
} targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); /* tap ifindex */
	__type(value, __u32); /* owning tgid */
} target_ifaces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct exit_key);
	__type(value, __u64);
} vm_exits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct exit_key);
	__type(value, __u64);
} vm_uexits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_TARGETS);
	__type(key, __u32);
	__type(value, struct vm_counters);
} vm_stats SEC(".maps");

/* Per thread; only the owning thread writes, so no atomics are needed. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct vcpu_counters);
} vcpu_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u32); /* tid */
	__type(value, __u64);
} runq_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); /* tid */
	__type(value, struct hist);
} runq_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct blk_key);
	__type(value, struct blk_start);
} blk_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); /* dev_t */
	__type(value, struct hist);
} blk_dev_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TARGETS);
	__type(key, __u32); /* tgid that issued the request */
	__type(value, struct hist);
} blk_vm_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); /* dev_t */
	__type(value, __u64);
} blk_errors SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct drop_key);
	__type(value, __u64);
} skb_drops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct rl_key);
	__type(value, __u64);
} event_rl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline bool is_target(__u32 tgid)
{
	return bpf_map_lookup_elem(&targets, &tgid) != NULL;
}

static __always_inline __u32 current_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline __u32 log2l(__u64 v)
{
	__u32 r = 0;
#pragma unroll
	for (int i = 32; i > 0; i >>= 1) {
		if (v >= (1ULL << i)) {
			v >>= i;
			r += i;
		}
	}
	return r;
}

/* hist_add may run concurrently on several CPUs for the same key. */
static __always_inline void hist_add(void *map, __u32 key, __u64 us)
{
	struct hist *h = bpf_map_lookup_elem(map, &key);
	if (!h) {
		struct hist zero = {};
		bpf_map_update_elem(map, &key, &zero, BPF_NOEXIST);
		h = bpf_map_lookup_elem(map, &key);
		if (!h)
			return;
	}
	__u32 slot = log2l(us);
	if (slot >= HIST_SLOTS)
		slot = HIST_SLOTS - 1;
	__sync_fetch_and_add(&h->slots[slot], 1);
	__sync_fetch_and_add(&h->count, 1);
	__sync_fetch_and_add(&h->sum_us, us);
	if (us > h->max_us)
		h->max_us = us;
}

static __always_inline struct vm_counters *vm_counters_get(__u32 tgid)
{
	struct vm_counters *c = bpf_map_lookup_elem(&vm_stats, &tgid);
	if (c)
		return c;
	struct vm_counters zero = {};
	bpf_map_update_elem(&vm_stats, &tgid, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&vm_stats, &tgid);
}

static __always_inline void count_key(void *map, __u32 tgid, __u32 reason)
{
	struct exit_key k = { .tgid = tgid, .reason = reason };
	__u64 *v = bpf_map_lookup_elem(map, &k);
	if (v) {
		(*v)++; /* per-CPU value */
	} else {
		__u64 one = 1;
		bpf_map_update_elem(map, &k, &one, BPF_NOEXIST);
	}
}

static __always_inline bool rate_limited(__u32 tgid, __u32 type)
{
	struct rl_key k = { .tgid = tgid, .type = type };
	__u64 now = bpf_ktime_get_ns();
	__u64 *last = bpf_map_lookup_elem(&event_rl, &k);
	if (last && now - *last < EVENT_GAP_NS)
		return true;
	bpf_map_update_elem(&event_rl, &k, &now, BPF_ANY);
	return false;
}

static __always_inline struct event *event_new(__u32 type, __u32 tgid)
{
	if (rate_limited(tgid, type))
		return NULL;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return NULL;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = bpf_ktime_get_ns();
	e->type = type;
	e->tgid = tgid;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

/* ---------------------------------------------------------------- KVM */

SEC("tracepoint/kvm/kvm_exit")
int kvm_exit(void *ctx)
{
	__u32 tgid = current_tgid();
	if (!is_target(tgid))
		return 0;

	__u32 reason = 0;
	TP_READ(reason, off_kvm_exit_reason);
	if (off_kvm_exit_reason2) {
		__s32 ret = 0;
		TP_READ(ret, off_kvm_exit_reason2);
		reason = (reason & 0xffff) | ((__u32)(ret & 0xff) << 16);
	}
	count_key(&vm_exits, tgid, reason);

	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct vcpu_counters *vc = bpf_map_lookup_elem(&vcpu_stats, &tid);
	if (vc) {
		vc->exits++;
	} else {
		struct vcpu_counters n = { .exits = 1 };
		bpf_map_update_elem(&vcpu_stats, &tid, &n, BPF_NOEXIST);
	}
	return 0;
}

#define KVM_EXIT_UNKNOWN 0
#define KVM_EXIT_SHUTDOWN 8
#define KVM_EXIT_FAIL_ENTRY 9
#define KVM_EXIT_INTERNAL_ERROR 17
#define KVM_EXIT_SYSTEM_EVENT 24
#define KVM_EXIT_ARM_NISV 28
#define KVM_EXIT_NOTIFY 37
#define KVM_EXIT_MEMORY_FAULT 39

SEC("tracepoint/kvm/kvm_userspace_exit")
int kvm_userspace_exit(void *ctx)
{
	__u32 tgid = current_tgid();
	if (!is_target(tgid))
		return 0;

	__u32 reason = 0;
	__s32 err = 0;
	TP_READ(reason, off_uexit_reason);
	TP_READ(err, off_uexit_errno);
	if (err < 0)
		err = -err;

	/* With an errno the exit reason is stale. 4 = EINTR, 11 = EAGAIN. */
	bool report;
	if (err) {
		report = err != 4 && err != 11;
		reason = 0xffff;
	} else {
		count_key(&vm_uexits, tgid, reason);
		report = reason == KVM_EXIT_UNKNOWN || reason == KVM_EXIT_SHUTDOWN ||
			 reason == KVM_EXIT_FAIL_ENTRY || reason == KVM_EXIT_INTERNAL_ERROR ||
			 reason == KVM_EXIT_SYSTEM_EVENT || reason == KVM_EXIT_ARM_NISV ||
			 reason == KVM_EXIT_NOTIFY || reason == KVM_EXIT_MEMORY_FAULT;
	}
	if (!report)
		return 0;

	struct event *e = event_new(EV_KVM_UEXIT, tgid);
	if (!e)
		return 0;
	e->a = reason;
	e->b = err;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/kvm/kvm_emulate_insn")
int kvm_emulate_insn(void *ctx)
{
	__u32 tgid = current_tgid();
	if (!is_target(tgid))
		return 0;

	__u8 failed = 0;
	TP_READ(failed, off_emul_failed);
	if (!failed)
		return 0;

	struct vm_counters *c = vm_counters_get(tgid);
	if (c)
		c->emul_failures++;

	struct event *e = event_new(EV_KVM_EMUL_FAIL, tgid);
	if (!e)
		return 0;
	__u64 rip = 0;
	TP_READ(rip, off_emul_rip);
	e->a = rip;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/kvm/kvm_inj_exception")
int kvm_inj_exception(void *ctx)
{
	__u32 tgid = current_tgid();
	if (!is_target(tgid))
		return 0;

	struct vm_counters *c = vm_counters_get(tgid);
	if (c)
		c->exceptions++;

	__u8 vector = 0;
	TP_READ(vector, off_exc_vector);
	/* Only double faults and machine checks are always worth an event. */
	if (vector != 8 && vector != 18)
		return 0;

	struct event *e = event_new(EV_KVM_EXCEPTION, tgid);
	if (!e)
		return 0;
	__u32 code = 0;
	TP_READ(code, off_exc_errcode);
	e->a = vector;
	e->b = code;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/kvm/kvm_inj_virq")
int kvm_inj_virq(void *ctx)
{
	__u32 tgid = current_tgid();
	if (!is_target(tgid))
		return 0;
	struct vm_counters *c = vm_counters_get(tgid);
	if (c)
		c->irq_injections++;
	return 0;
}

SEC("tracepoint/kvm/kvm_vcpu_wakeup")
int kvm_vcpu_wakeup(void *ctx)
{
	__u32 tgid = current_tgid();
	if (!is_target(tgid))
		return 0;

	__u64 ns = 0;
	__u8 waited = 0;
	TP_READ(ns, off_wake_ns);
	TP_READ(waited, off_wake_waited);

	struct vm_counters *c = vm_counters_get(tgid);
	if (c) {
		if (waited) {
			c->halt_waits++;
			c->halt_wait_ns += ns;
		} else {
			c->halt_polls_ok++;
		}
	}
	if (waited) {
		__u32 tid = (__u32)bpf_get_current_pid_tgid();
		struct vcpu_counters *vc = bpf_map_lookup_elem(&vcpu_stats, &tid);
		if (vc)
			vc->halt_waits++;
	}
	return 0;
}

/* ---------------------------------------------------------- scheduler */

struct task_struct___o {
	volatile long state;
} __attribute__((preserve_access_index));

struct task_struct___x {
	unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline long task_state(struct task_struct *t)
{
	struct task_struct___x *tx = (void *)t;
	if (bpf_core_field_exists(tx->__state))
		return BPF_CORE_READ(tx, __state);
	return BPF_CORE_READ((struct task_struct___o *)t, state);
}

static __always_inline void runq_enqueue(struct task_struct *p)
{
	__u32 tgid = BPF_CORE_READ(p, tgid);
	if (!is_target(tgid))
		return;
	__u32 pid = BPF_CORE_READ(p, pid);
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&runq_start, &pid, &ts, BPF_ANY);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	runq_enqueue(p);
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	runq_enqueue(p);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	/* A task preempted while runnable goes straight back to the queue. */
	if (task_state(prev) == TASK_RUNNING)
		runq_enqueue(prev);

	__u32 tgid = BPF_CORE_READ(next, tgid);
	if (!is_target(tgid))
		return 0;
	__u32 pid = BPF_CORE_READ(next, pid);
	__u64 *start = bpf_map_lookup_elem(&runq_start, &pid);
	if (!start)
		return 0;
	__u64 delta = bpf_ktime_get_ns() - *start;
	bpf_map_delete_elem(&runq_start, &pid);
	hist_add(&runq_hist, pid, delta / 1000);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *p)
{
	__u32 tgid = BPF_CORE_READ(p, tgid);
	if (!is_target(tgid))
		return 0;
	__u32 pid = BPF_CORE_READ(p, pid);
	bpf_map_delete_elem(&runq_start, &pid);
	bpf_map_delete_elem(&runq_hist, &pid);
	bpf_map_delete_elem(&vcpu_stats, &pid);
	if (pid != tgid)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = bpf_ktime_get_ns();
	e->type = EV_EXIT;
	e->tgid = tgid;
	e->tid = pid;
	e->cpu = bpf_get_smp_processor_id();
	e->a = BPF_CORE_READ(p, exit_code);
	BPF_CORE_READ_STR_INTO(&e->comm, p, comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#define SIGILL 4
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGSEGV 11
#define SIGTERM 15
#define SIGSYS 31

SEC("tp_btf/signal_generate")
int BPF_PROG(signal_generate, int sig, struct kernel_siginfo *info, struct task_struct *task,
	     int group, int result)
{
	if (result != 0) /* TRACE_SIGNAL_DELIVERED */
		return 0;
	if (sig != SIGILL && sig != SIGABRT && sig != SIGBUS && sig != SIGFPE &&
	    sig != SIGKILL && sig != SIGSEGV && sig != SIGTERM && sig != SIGSYS)
		return 0;
	__u32 tgid = BPF_CORE_READ(task, tgid);
	if (!is_target(tgid))
		return 0;

	struct event *e = event_new(EV_SIGNAL, tgid);
	if (!e)
		return 0;
	e->tid = BPF_CORE_READ(task, pid);
	e->a = sig;
	e->b = current_tgid();
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* -------------------------------------------------------------- block */

SEC("tracepoint/block/block_rq_issue")
int block_rq_issue(void *ctx)
{
	struct blk_key k = {};
	__u32 nr = 0;
	TP_READ(k.dev, off_rqi_dev);
	TP_READ(k.sector, off_rqi_sector);
	TP_READ(nr, off_rqi_nr);
	if (!nr)
		return 0;

	__u32 tgid = current_tgid();
	struct blk_start s = {
		.ts = bpf_ktime_get_ns(),
		.tgid = is_target(tgid) ? tgid : 0,
	};
	bpf_map_update_elem(&blk_start, &k, &s, BPF_ANY);
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int block_rq_complete(void *ctx)
{
	struct blk_key k = {};
	__u32 nr = 0;
	__s32 err = 0;
	TP_READ(k.dev, off_rqc_dev);
	TP_READ(k.sector, off_rqc_sector);
	TP_READ(nr, off_rqc_nr);
	TP_READ(err, off_rqc_error);

	if (err) {
		__u32 dev = k.dev;
		__u64 *n = bpf_map_lookup_elem(&blk_errors, &dev);
		if (n) {
			__sync_fetch_and_add(n, 1);
		} else {
			__u64 one = 1;
			bpf_map_update_elem(&blk_errors, &dev, &one, BPF_NOEXIST);
		}
		struct event *e = event_new(EV_BLK_ERROR, dev);
		if (e) {
			e->a = dev;
			e->b = k.sector;
			e->c = err;
			e->d = nr;
			bpf_ringbuf_submit(e, 0);
		}
	}

	struct blk_start *s = bpf_map_lookup_elem(&blk_start, &k);
	if (!s)
		return 0;
	__u64 us = (bpf_ktime_get_ns() - s->ts) / 1000;
	__u32 tgid = s->tgid;
	bpf_map_delete_elem(&blk_start, &k);

	hist_add(&blk_dev_hist, k.dev, us);
	if (tgid)
		hist_add(&blk_vm_hist, tgid, us);
	return 0;
}

/* ------------------------------------------------------------ network */

static __always_inline void count_drop(struct sk_buff *skb, __u32 reason)
{
	struct net_device *dev = BPF_CORE_READ(skb, dev);
	if (!dev)
		return;
	__u32 ifindex = BPF_CORE_READ(dev, ifindex);
	if (!bpf_map_lookup_elem(&target_ifaces, &ifindex))
		return;
	struct drop_key k = { .ifindex = ifindex, .reason = reason };
	__u64 *v = bpf_map_lookup_elem(&skb_drops, &k);
	if (v) {
		__sync_fetch_and_add(v, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&skb_drops, &k, &one, BPF_NOEXIST);
	}
}

/* Kernels >= 5.17 pass a drop reason; the loader picks the variant that
 * matches the running kernel. */
SEC("tp_btf/kfree_skb")
int BPF_PROG(kfree_skb_reason, struct sk_buff *skb, void *location, int reason)
{
	count_drop(skb, reason);
	return 0;
}

SEC("tp_btf/kfree_skb")
int BPF_PROG(kfree_skb, struct sk_buff *skb, void *location)
{
	count_drop(skb, 0);
	return 0;
}

/* ----------------------------------------------------- memory, hardware */

SEC("tracepoint/oom/mark_victim")
int oom_mark_victim(void *ctx)
{
	__s32 pid = 0;
	TP_READ(pid, off_oom_pid);
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = bpf_ktime_get_ns();
	e->type = EV_OOM_VICTIM;
	e->tgid = pid;
	e->cpu = bpf_get_smp_processor_id();
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/mce/mce_record")
int mce_record(void *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	__u64 status = 0, addr = 0, mcg = 0;
	__u8 bank = 0;
	TP_READ(status, off_mce_status);
	TP_READ(addr, off_mce_addr);
	TP_READ(bank, off_mce_bank);
	TP_READ(mcg, off_mce_mcgstatus);
	e->ts = bpf_ktime_get_ns();
	e->type = EV_MCE;
	e->cpu = bpf_get_smp_processor_id();
	e->a = status;
	e->b = addr;
	e->c = bank;
	e->d = mcg;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
