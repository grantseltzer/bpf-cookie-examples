package main

import (
	"errors"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64 -type event bpf ./tail_calls.c -- -I../../bpf/helpers

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize:  100000,
			LogLevel: ebpf.LogLevelInstruction,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier Issue\n%s\n", ve)
		}
		log.Fatalf("error loading: %s\n", err)
	}
	defer objs.Close()

	//Todo: Attach `uprobe__instrument` to an executable's function, specified as os.Args

	time.Sleep(time.Minute)
}
