struct bpf_map_def SEC("maps") cookie_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u8),
	.value_size  = sizeof(instruction_set_t),
	.max_entries = 10, 
};

// output ringbuffer
struct bpf_map_def SEC("maps") events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1<<24,
};
