package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64 -type filters -type event bpf ./multiple_filter.c -- -I../../bpf/helpers

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, &ebpf.CollectionOptions{})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier Issue\n%s\n", ve)
		}
		log.Fatalf("error loading: %s\n", err)
	}
	defer objs.Close()

	var indexInFilterMap uint64 = 1
	filters := bpfFilters{
		Uid: 0,
		Gid: 0,
	}
	err = objs.FiltersMap.Update(indexInFilterMap, filters, ebpf.UpdateNoExist)
	if err != nil {
		log.Fatal("can't update filter map: ", err)
	}

	_, err = link.Kprobe("do_unlinkat", objs.KprobeDoUnlinkat, &link.KprobeOptions{
		Cookie: indexInFilterMap,
	})
	if err != nil {
		log.Fatal(err)
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
		fmt.Printf("do_unlinkat occured with uid: \n", event.Uid)
	}
}
