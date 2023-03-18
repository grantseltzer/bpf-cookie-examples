package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64 -type event bpf ../../bpf/use_vm.bpf.c -- -I../../bpf/helpers

/*
- Read executable/path flags
- Retrieve DWARF from executable
- Find symbol in DWARF, populate a struct with its params and their types
- Generate instructions from ^
- Put instructions in cookie map
- Set index in cookie map as the cookie
- Poll for output
*/
func main() {

	executable_path := flag.String("executable", "", "path to executable to instrument")
	symbol_name := flag.String("symbol", "", "symbol to instrument in executable")
	flag.Parse()

	if *executable_path == "" || *symbol_name == "" {
		log.Fatal("executable path and symbol name must be specified with flags. Use `-h`")
	}

	executable, err := link.OpenExecutable(*executable_path)
	if err != nil {
		log.Fatal(err)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	err = loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogDisabled: false,
			LogSize:     ebpf.DefaultVerifierLogSize * 15,
			LogLevel:    ebpf.LogLevelInstruction,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("%+v\n", ve)
		}
	}
	defer objs.Close()

	cookie := create_dummy_cookie()
	encoded_cookie := encode_cookie(cookie)
	index := 1
	err = objs.bpfMaps.CookieMap.Update(index, encoded_cookie, ebpf.UpdateNoExist)
	if err != nil {
		log.Fatal(err)
	}

	l, err := executable.Uprobe(*symbol_name, objs.UprobeInstrument, &link.UprobeOptions{
		Cookie: uint64(index),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

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
			&event)
		if err != nil {
			log.Printf("failed to interpret binary data from raw sample")
			continue
		}

		eventJSON, err := json.MarshalIndent(event, "", " ")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s\n", eventJSON)
	}
}
