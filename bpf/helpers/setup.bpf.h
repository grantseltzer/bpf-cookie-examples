/*
- Need setup init for the start and end of the program for creating an array and then sending the populated one over a ringbuffer
- Creating the stack (a local storage? struct on ringbuffer? )
*/

#include "bpf_helper_defs.h"

// map of arrays
// create an actual array of size 512

static __always_inline [512]char
create_array() {
    
}