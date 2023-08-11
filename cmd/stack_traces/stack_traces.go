package main

import (
	"bytes"
	"debug/elf"
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64 -type event bpf ./stack_traces.c -- -I../../bpf/helpers

var syms []elf.Symbol

func resolveSymbolNameFromFPOffset(fpOffset uint64) string {

	var (
		min     = 0
		max     = len(syms) - 1
		halfway = 0
	)

	for {
		halfway = (min + max) / 2

		if syms[max].Value <= fpOffset {
			return syms[max].Name
		}

		if syms[min].Value == fpOffset || max-min == 1 {
			return syms[min].Name
		}

		if syms[halfway].Value == fpOffset {
			return syms[halfway].Name
		}

		if fpOffset > syms[halfway].Value {
			min = halfway
		}

		if fpOffset < syms[halfway].Value {
			max = halfway
		}
	}
}

func main() {

	f, err := elf.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	syms, err = f.Symbols()
	if err != nil {
		log.Fatal(err)
	}

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
	err = loadBpfObjects(&objs, nil)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier Issue\n%s\n", ve)
		}

		log.Fatalf("error loading: %s\n", err)
	}
	defer objs.Close()

	symbolIDToName := map[uint64]string{}
	symbolNamesToID := map[string]uint64{}
	for i := range os.Args[2:] {
		symbolIDToName[uint64(i)] = os.Args[2+i]
		symbolNamesToID[os.Args[2+i]] = uint64(i)
	}

	for symName, symID := range symbolNamesToID {

		l1, err := executable.Uprobe(symName, objs.UprobeWalkStackManually, &link.UprobeOptions{
			Cookie: symID,
		})
		if err != nil {
			log.Fatal(err)
		}
		defer l1.Close()
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

		fmt.Printf("%s\n", symbolIDToName[event.EventId])
		for i := range event.ReturnAddrs {
			fmt.Printf("\t0x%x: %s\n", event.ReturnAddrs[i], resolveSymbolNameFromFPOffset(event.ReturnAddrs[i]))
		}
	}
}
