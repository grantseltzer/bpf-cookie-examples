package main

import (
	"errors"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64 -type event bpf ./verifier_hook.c -- -I../../bpf/helpers

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}

	err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize:  4096,
			LogLevel: ebpf.LogLevelStats,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("%+v\n", ve)
		}
	}
	defer objs.Close()
}
