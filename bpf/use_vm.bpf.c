#include <stdint.h>
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "go_runtime_types.bpf.h"
#include "maps.bpf.h"
#include "instructions.bpf.h"

struct event {};
const struct event *unused __attribute__((unused));

SEC("uprobe/instrument")
int uprobe__instrument(struct pt_regs *ctx)
{
    // Read in bpf cookie 
    // Retrieve the set of instructions from the cookie map
    // Execute the instructions
    // Submit output array over ringbuffer

    __u64 cookie_index = bpf_get_attach_cookie(ctx);
    __u64* instructions = (__u64*)bpf_map_lookup_elem(&cookie_map, cookie_index);
    if (!instructions) {
        return 0;
    }

    // cap stack size at 512, and 100 instructions
    __u64 instr;
    __u64 value;
    __u64 current_op;
    __u64 stack[512];

    for (int i; i < 100; i++) {

        instr = *(instructions+(i*8));

        // Not reading instruction arguments, read 
        // the opcode
        if (current_op == OPCODE_INVALID_INSTRUCTION) {
            current_op = instr;
            continue;
        }

        if (current_op == OPCODE_READ_REGISTER) {
            if (instr > 31) {
                bpf_printk("invalid register to read from");
                return 0;
            }

            bpf_probe_read(&value, sizeof(__u64), ctx->regs[instr]);
            push(value, &stack);
            current_op = OPCODE_INVALID_INSTRUCTION;
            continue;
        }

        
    }

    return 0;
}

void push(__u64* value, __u64* stack[512]) {

}
