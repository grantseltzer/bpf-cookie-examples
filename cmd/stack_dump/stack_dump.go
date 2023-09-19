package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64 -type event bpf ./stack_dump.c -- -I../../bpf/helpers

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	binaryPath := os.Args[1]

	executable, err := link.OpenExecutable(binaryPath)
	if err != nil {
		log.Fatal(err)
	}

	f, err := elf.Open(binaryPath)
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

	//bininspect
	fieldIDs := make([]bininspect.FieldIdentifier, 0)

	r, err := bininspect.InspectWithDWARF(f, os.Args[2:], fieldIDs)
	if err != nil {
		log.Fatal(err)
	}
	b, err := json.MarshalIndent(r.Functions, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", string(b))
	////////

	symbolIDToName := map[uint64]string{}
	symbolNamesToID := map[string]uint64{}
	for i := range os.Args[2:] {
		symbolIDToName[uint64(i)] = os.Args[2+i]
		symbolNamesToID[os.Args[2+i]] = uint64(i)
	}

	for symName, symID := range symbolNamesToID {

		l1, err := executable.Uprobe(symName, objs.UprobeDumpStack, &link.UprobeOptions{
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

		b, err := json.MarshalIndent(event, "", " ")
		if err != nil {
			log.Printf("failed to marshal to json: %s\n", err)
			continue
		}
		log.Printf("%s\n", string(b))
	}
}
