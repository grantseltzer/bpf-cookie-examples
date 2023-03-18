// Hash map where k = TID, v = goroutine ID
// used to retrieve goroutine ids for triggered
// events by setting the goroutine ID from
// instrumenting runtime.execute
//
struct bpf_map_def SEC("maps") cookie_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64),
	.max_entries = 1<<24, 
};

// output ringbuffer
struct bpf_map_def SEC("maps") events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1<<24,
};
