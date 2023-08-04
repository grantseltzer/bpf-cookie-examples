package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64 -type event bpf ./event_id.c -- -I../../bpf/helpers

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	executable, err := link.OpenExecutable(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	err = loadBpfObjects(&objs, &ebpf.CollectionOptions{})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier Issue\n%s\n", ve)
		}
		log.Fatalf("error loading: %s\n", err)
	}
	defer objs.Close()

	symbolIDToName := map[uint64]string{
		1: "main.foobar",
		2: "main.bazbuz",
	}

	symbolNamesToID := map[string]uint64{
		"main.foobar": 1,
		"main.bazbuz": 2,
	}

	for symName, symID := range symbolNamesToID {
		l, err := executable.Uprobe(symName, objs.UprobeInstrument, &link.UprobeOptions{
			Cookie: symID,
		})
		defer l.Close()
		if err != nil {
			log.Fatal(err)
		}
	}

	// Open the bpf ringbuffer
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()

	var event bpfEvent

	for {
		// Blocking wait for events off ringbuffer
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}

		// Parse the raw bytes from struct representation
		// into the source struct definition
		err = binary.Read(
			bytes.NewBuffer(record.RawSample),
			binary.LittleEndian,
			&event,
		)

		if err != nil {
			log.Printf("failed to interpret binary data from raw sample")
			continue
		}

		fmt.Printf("The symbol %s had the first 50 bytes: %w\n", symbolIDToName[event.EventId], event.StackContent)
	}
}
