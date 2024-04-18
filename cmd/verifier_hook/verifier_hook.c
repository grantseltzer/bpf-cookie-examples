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
    char some_array[10];
    struct pt_regs regs;
};
const struct event *unused __attribute__((unused));

SEC("uprobe/too_many_instructions")
int uprobe__too_many_instructions(struct pt_regs *ctx)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    int i;
    char y;
    void* stackAddr = (void*)ctx->sp;

    for (i = 0; i < 999999999; i++) {
        char *x = (char*)stackAddr+1;
        bpf_probe_read(&y, sizeof(y), x);
        e->some_array[1] = y;
    }

    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

SEC("uprobe/invalid_mem_access")
int uprobe__invalid_mem_access(struct pt_regs *ctx)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    int i;
    for (i = 0; i < 40; i++) {
        e->some_array[i] = 'y';
    }

    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

SEC("uprobe/example_issue")
int uprobe__example_issue(struct pt_regs *ctx)
{
    void* r2 = (void*)(ctx+10000);
    char val;
    bpf_probe_read(&val, sizeof(val), r2);
    return 0;
}

char __license[] SEC("license") = "GPL";
