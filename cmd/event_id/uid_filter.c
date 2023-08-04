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
    int uid;
};
const struct event *unused __attribute__((unused));

SEC("kprobe/do_unlinkat")
int kprobe__do_unlinkat(struct pt_regs *ctx)
{
    __u64 target_uid = bpf_get_attach_cookie(ctx);
    __u64 uid = bpf_get_current_uid_gid();

    if (target_uid != uid) {
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
