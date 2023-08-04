#include <stdint.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct event {
    int uid;
};
const struct event *unused __attribute__((unused));

SEC("kprobe/do_unlinkat")
int kprobe__do_unlinkat(struct pt_regs *ctx)
{
    __u64 map_index_for_filter = bpf_get_attach_cookie(ctx);
    
    __u64 uid = bpf_get_current_uid_gid(); // TODO:extract seperate uid/gid

    // TODO: Get the filter struct from the cookie map using cookie map_index_for_filter

 
    if (target_uid != uid) { //TODO: compare the fields in struct 
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
