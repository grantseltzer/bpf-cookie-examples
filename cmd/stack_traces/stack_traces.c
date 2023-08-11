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
    __u64 event_id;
    __u64 return_addrs[10];
};
const struct event *unused __attribute__((unused));


SEC("uprobe/walk_stack_manually")
int uprobe__walk_stack_manually(struct pt_regs *ctx)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->event_id = bpf_get_attach_cookie(ctx);

    __u64 bp = ctx->regs[29];
    bpf_probe_read(&bp, sizeof(__u64), (void*)bp); // dereference bp to get current stackframe

    __u64 ret_addr = ctx->regs[30]; // when bpf prog enters, the return address hasn't yet been written to the stack

    int i;
    for (i = 0; i < 10; i++) 
    {
        if (bp == 0) {
            break;
        }
        bpf_probe_read(&e->return_addrs[i], sizeof(__u64), &ret_addr);
        bpf_probe_read(&ret_addr, sizeof(__u64), (void*)(bp-8));
        bpf_probe_read(&bp, sizeof(__u64), (void*)bp);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
