//go:build ignore

#include <stdint.h>
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "go_runtime_types.bpf.h"

// Hash map where k = TID, v = goroutine ID
// used to retrieve goroutine ids for triggered
// events by setting the goroutine ID from
// instrumenting runtime.execute
//
struct bpf_map_def SEC("maps") tgs = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(*u32),
	.max_entries = 1<<24, 
};

// output ringbuffer
struct bpf_map_def SEC("maps") events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1<<24,
};

struct event {
    u32 pid;
    u64 go_routine_id;
};
const struct event *unused __attribute__((unused));

SEC("uprobe/test_function")
int uprobe__test_function(struct pt_regs *ctx)
{
    // allocate space for the event on ringbuf

    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) {
        bpf_printk("NO SPACE;");
        return 0;
    }
    
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 tgid = pidtgid >> 32;
    u32 tid = pidtgid;

    u64 *goid = bpf_map_lookup_elem(&tgs, &tid);
    if (!goid) {
        bpf_printk("NULL KEY");
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    event->go_routine_id = *goid;
    event->pid = tgid;
    bpf_printk("submitting!\n");
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("uprobe/runtime_execute")
int uprobe__runtime_execute(struct pt_regs *ctx)
{
    // According to go ABI first register (regs[0]) should contain pointer
    // to g since that's the first parameter, as a pointer,
    // to the runtime.execute function
    //
    // Want the field 'goid' from struct g
    //
    // ctx->regs[0] = *struct g
    // g->goid is go routine id
    //

    struct g g_value;
    bpf_probe_read((void*)&g_value, sizeof(struct g), (void*)ctx->regs[0]);

    u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tgs, &tid, &g_value.goid, 0);

    return 0;
}

char __license[] SEC("license") = "GPL";
