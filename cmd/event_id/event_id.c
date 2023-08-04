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
    char stack_content[50];
};
const struct event *unused __attribute__((unused));

SEC("uprobe/instrument")
int uprobe_instrument(struct pt_regs *ctx)
{
    __u64 event_id = bpf_get_attach_cookie(ctx);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->event_id = event_id;

    bpf_probe_read(&e->stack_content, 50, &ctx->sp);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
