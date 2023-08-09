#include <stdint.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

// output ringbuffer
struct bpf_map_def SEC("maps") events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1<<24,
};

struct event {
    __u8 event_id;
	__u64 cookie;
};
const struct event *unused __attribute__((unused));

// This one gets put in progarray
SEC("uprobe/call_me")
int uprobe__call_me(struct pt_regs *ctx) 
{
	__u64 cookie = bpf_get_attach_cookie(ctx);
	bpf_printk("from tail called bpf: %d\n", cookie);

	return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
	__array(values, int ());
} progarray SEC(".maps") = {
	.values = {
		[0] = (void *)&uprobe__call_me,
	},
};

static __noinline
int do_tail_call(struct pt_regs *ctx)
{
	bpf_tail_call(ctx, &progarray, 0);
	return 0;
}

SEC("uprobe/instrument")
int uprobe__instrument(struct pt_regs *ctx) 
{
	__u64 cookie = bpf_get_attach_cookie(ctx);
	bpf_printk("from top level bpf: %d\n", cookie);
    return do_tail_call(ctx);  
}

char LICENSE[] SEC("license") = "GPL";
