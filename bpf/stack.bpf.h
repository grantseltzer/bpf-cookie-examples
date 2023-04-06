/*
    Implementation of the vm stack with an array
*/
static __always_inline int push(__u16* value, __u16 stack[STACK_SIZE], __int8_t* top) {

    if (*top == -1) {
        // Uninitialized stack
        stack[0] = *value;
        *top = 0;
    } else if (*top == STACK_SIZE-1) {
        // Stack is full
        return 1;
    } else {
        // Push onto stack
        stack[(*top) + 1] = *value;
        (*top) += 1;
    }
    return 0;
}

static __always_inline __u8 pop(__u16 stack[STACK_SIZE], __int8_t* top) {
    __u16 popValue = 0;
    
    if((*top) == -1) {
        // Empty stack
        return 0;
    } else {
        popValue = stack[(*top)];
        *top = (*top) - 1;
    }
    return popValue;
}
