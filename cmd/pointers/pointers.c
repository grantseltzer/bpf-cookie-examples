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
    char configContent[500];
};
const struct event *unused __attribute__((unused));

SEC("uprobe/instrument")
int uprobe_instrument(struct pt_regs *ctx)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    __u64 length;
    bpf_probe_read(&length, 8, &ctx->regs[1]);

    if (length < 500) {
        bpf_probe_read(e->configContent, length, (void*)ctx->regs[0]);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
