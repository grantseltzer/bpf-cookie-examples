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
    char stack_content[50];
};
const struct event *unused __attribute__((unused));

SEC("uprobe/dump_stack")
int uprobe__dump_stack(struct pt_regs *ctx)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    int i;
    char y;
    void* stackAddr = (void*)ctx->sp;

    for (i = 0; i < 50; i++) {
        char *x = (char*)stackAddr+i;
        bpf_probe_read(&y, sizeof(y), x);
        e->stack_content[i] = y;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
