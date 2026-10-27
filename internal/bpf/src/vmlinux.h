/* Minimal, architecture-neutral kernel type definitions.
 *
 * Only the fields hyperview reads are declared. Every struct carries
 * preserve_access_index, so field offsets are relocated against the running
 * kernel's BTF at load time (CO-RE) and the same object works on x86_64 and
 * arm64 across kernel versions.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;
typedef int pid_t;

enum {
	false = 0,
	true = 1,
};

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct task_struct {
	pid_t pid;
	pid_t tgid;
	int exit_code;
	char comm[16];
};

struct net_device {
	int ifindex;
};

struct sk_buff {
	struct net_device *dev;
};

struct kernel_siginfo;

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
