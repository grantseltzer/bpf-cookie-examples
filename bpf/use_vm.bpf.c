#include <stdint.h>
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "go_runtime_types.bpf.h"
#include "maps.bpf.h"
#include "instructions.bpf.h"

const int STACK_SIZE = 32;
const int MAX_OUTPUT_COUNT = 10;

struct event {
	__u64 array[10];
};
const struct event *unused __attribute__((unused));

static __always_inline int push(__u64* value, __u64 stack[512], int* top) {

    // Uninitialized stack
    if (*top == -1) {
        stack[STACK_SIZE] = *value;
        *top = STACK_SIZE - 1;
    } else if (*top == 0) {
        // stack is full
        bpf_printk("stack is full, can't push");
        return 1;
    } else {
        stack[(*top) - 1] = *value;
        (*top) -= 1;
    }
    return 0;
}

static __always_inline __u64 pop(__u64 stack[32], int* top) {
    __u64 popValue;
    if(*top == -1) {
        bpf_printk("stack is empty, can't pop");
        return 0;
    } else {
        popValue = stack[*top];
        if ((*top) == STACK_SIZE -1) {
            *top = -1;
        } else {
            *top = *top + 1;
        }
    }
    return popValue;
}

SEC("uprobe/instrument")
int uprobe__instrument(struct pt_regs *ctx)
{
    // Read in bpf cookie 
    // Retrieve the set of instructions from the cookie map
    // Execute the instructions
    // Submit output array over ringbuffer
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        bpf_printk("couldn't reserve on ringbuf");
        return 0;
    }
    
    __u64 cookie_index = bpf_get_attach_cookie(ctx);
    __u64* instructions = (__u64*)bpf_map_lookup_elem(&cookie_map, &cookie_index);
    if (!instructions) {
        return 0;
    }

    // FIXME:
    // The value in the cookie map has to be a known size
    // before traversing through it (the `instr = *(instrucitons+(i*8))` line)
    // otherwise we get permission denied.
    // Perhaps an array?


    // cap stack size at 512, and 16 instructions
    __u64 instr;
    __u64 value;
    __u64 current_op;
    
    int err;

    int stack_top = -1;
    __u64 stack[32];
    int output_counter = 0;

    int i;
    for (i = 0; i < 32; i++) {

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

            bpf_probe_read(&value, sizeof(__u64), &ctx->regs[instr]);
            err = push(&value, stack, &stack_top);
            if (err != 0) {
                return 0;
            }
            current_op = OPCODE_INVALID_INSTRUCTION;
            continue;
        }

        if (current_op == OPCODE_APPEND_TO_ARRAY) {
            value = pop(stack, &stack_top);
            if (output_counter < MAX_OUTPUT_COUNT) {
                e->array[output_counter] = value;
            } else {
                bpf_printk("reached max output values");
                return 0;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char __license[] SEC("license") = "GPL";
