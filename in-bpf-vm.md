## Experiment

- A bpf function that contains logic just to execute a single instruction (the instruction is our high level defined VM)
- On the original trigger, the cookie is retrieved which points to an index in a map which contains the following structure:

{
    instructions = []Instruction,
    vmStack = []int,
}

- The first instruction is popped from the instruction array, and executed. The stack is used for this to store between tail calls
- If the instruction is anything but "return", a tail call occurs which uses the same cookie, and which points to the shared state
  that the cookie points to 

## Questions

- What is the tail call limit (which theoretically would be the limit on number of instructions the VM could support)
- Are there other resource limits that the programs would share?
- Minimum kernel versions

## Thoughts on implementation

- First build a program which attaches a cookie and runs a tail call, ensure the cookie remains set
- Caching instructions/stack in the bpf map (Wouldn't have to limit in terms of number of instructions I think)