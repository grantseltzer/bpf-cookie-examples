#include <stdint.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "constants.bpf.h"
#include "types.bpf.h"
#include "maps.bpf.h"
#include "instructions.bpf.h"
#include "stack.bpf.h"

SEC("uprobe/instrument")
int uprobe__instrument(struct pt_regs *ctx)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    
    __u64 cookie_index = bpf_get_attach_cookie(ctx);
    instruction_set_t* instructions = (instruction_set_t*)bpf_map_lookup_elem(&cookie_map, &cookie_index);
    if (!instructions) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    instruction_t current_instruction;

    int err;
    __int8_t stack_top = -1;
    __u16 stack[STACK_SIZE] = {0};
    int output_counter = 0;

    int i;
    for (i = 0; i < MAX_INSTRUCTIONS; i++) {

        current_instruction = instructions->ins[i];
        u8 op = current_instruction.op;

        if (op == OPCODE_NOP) {
            continue;
        }

        else if (op == OPCODE_READ_REGISTER) {
            __u16 value;
            if (current_instruction.arg1 > 31) {
                bpf_ringbuf_discard(e, 0);
                return 0;
            }

            bpf_probe_read(&value, sizeof(__u64), &ctx->regs[current_instruction.arg1]);
            err = push(&value, stack, &stack_top);
            if (err != 0) {
                bpf_ringbuf_discard(e, 0);
                return 0;
            }
            continue;
        }

        else if (op == OPCODE_READ_STACK) {
            // __u16 value;
            // void* stackAddr = (void*)ctx->sp;
            
            // value = bpf_probe_read(&value, current_instruction.arg2, stackAddr+current_instruction.arg1);
            // err = push(&value, stack, &stack_top);
            // if (err != 0) {
            //     bpf_ringbuf_discard(e, 0);
            //     return 0;
            // }
            // continue;
        }

        // else if (op == OPCODE_DEREFERENCE) {
        //     // TODO
        // }

        else if (op == OPCODE_APPEND_TO_ARRAY) {
            __u32 value;
            value = pop(stack, &stack_top);
            if (output_counter < MAX_OUTPUT_COUNT) {
                e->array[output_counter] = value;
                output_counter++;
            }
        }
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
