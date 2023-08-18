package main

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
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

var syms *gosym.Table

func resolveSymbolNameFromFPOffset(fpOffset uint64) (string, string, int) {
	fileName, lineNumber, fn := syms.PCToLine(fpOffset)
	return fn.Name, fileName, lineNumber
}

func main() {

	f, err := elf.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	addr := f.Section(".text").Addr

	lineTableData, err := f.Section(".gopclntab").Data()
	if err != nil {
		log.Fatal(err)
	}
	lineTable := gosym.NewLineTable(lineTableData, addr)
	if err != nil {
		log.Fatal(err)
	}
	symtab := f.Section(".gosymtab")
	symTableData, err := symtab.Data()
	if err != nil {
		log.Fatal(err)
	}

	syms, err = gosym.NewTable(symTableData, lineTable)
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
			funcName, fileName, lineNum := resolveSymbolNameFromFPOffset(event.ReturnAddrs[i])
			fmt.Printf("\t0x%x: %s (%s:%d)\n", event.ReturnAddrs[i], funcName, fileName, lineNum)
		}
	}
}

func elfGoSyms(f *elf.File) (*gosym.Table, error) {
	text := f.Section(".text")
	symtab := f.Section(".gosymtab")
	pclntab := f.Section(".gopclntab")
	if text == nil || symtab == nil || pclntab == nil {
		return nil, nil
	}

	symdat, err := symtab.Data()
	if err != nil {
		return nil, err
	}
	pclndat, err := pclntab.Data()
	if err != nil {
		return nil, err
	}

	pcln := gosym.NewLineTable(pclndat, text.Addr)
	tab, err := gosym.NewTable(symdat, pcln)
	if err != nil {
		return nil, err
	}

	return tab, nil
}
