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
SEC("tc")
int tc__call_me(struct __sk_buff *skb) 
{
	__u64 cookie = bpf_get_attach_cookie(skb);
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
		[0] = (void *)&tc__call_me,
	},
};

static __noinline
int do_tail_call(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &progarray, 0);
	return 0;
}

SEC("tc")
int tc__instrument(struct __sk_buff *skb) 
{
	__u64 cookie = bpf_get_attach_cookie(skb);
	bpf_printk("from top level bpf: %d\n", cookie);
    return do_tail_call(skb);  
}

char LICENSE[] SEC("license") = "GPL";
