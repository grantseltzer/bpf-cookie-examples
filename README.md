# 16-bit bpf

Solves the problem of in-kernel filtering (instead of taking lots of data back up to user space)

Stack based vm, needs instructions for:
- reading from specific registers
- reading from specific offsets on program's stack
- Dereference addresses
- append to an array

- reading values from bpf maps
- writing to bpf maps

## Instructions

| Mnemonic | Description | Num Arguments | Example |
| - | - | - | - |
| RR | Read from register | 1 | `RR 0` - Read 8 byte value from register 0 and push onto stack
| RS | Read from stack | 2  | `RS 8 4` - Read from offset 8 off the program stack a value of size 4 and push onto stack
| DE | Dereference the address on the stack and push the 8 byte value onto the stack | 0 | `DE`
| AA | Append 8 bytes into array | 0 | `AA` - pop 8 byte value, write to the array

## Example

Tracing function `test_single_uint64(x uint64)`. uint64 is loaded in register 0. No returns, just have to retrieve this one value 

Instructions:
```
RR 0
AA
```