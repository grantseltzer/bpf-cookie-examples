#include <stdint.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct event {
    int uid;
};
const struct event *unused1 __attribute__((unused));

struct filters {
    int uid;
    int gid;
};
const struct filters *unused2 __attribute__((unused));

// output ringbuffer
struct bpf_map_def SEC("maps") events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1<<24,
};

struct bpf_map_def SEC("maps") filters_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(struct filters),
	.max_entries = 100, 
};

SEC("kprobe/do_unlinkat")
int kprobe__do_unlinkat(struct pt_regs *ctx)
{
    __u64 map_index_for_filter = bpf_get_attach_cookie(ctx);
    struct filters* filters = (struct filters*)bpf_map_lookup_elem(&filters_map, &map_index_for_filter);
    if (!filters) {
        bpf_printk("could not find filter");
        return 0;
    }
    __u64 giduid = bpf_get_current_uid_gid();
    __u32 gid = giduid>>32;
    __u32 uid = (__u32)giduid;
    if (filters->uid != uid) {
        bpf_printk("uid did not match");
        return 0;
    }
    if (filters->gid != gid) {
        bpf_printk("gid did not match");
        return 0;
    }

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->uid = uid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
