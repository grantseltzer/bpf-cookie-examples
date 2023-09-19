package main

import (
	"bytes"
	"debug/dwarf"
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

var inlinedFuncsMap map[uint64][]*dwarf.Entry
var reader *dwarf.Reader

func dwarfReadInlinedFunctions(binaryPath string) error {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return err
	}

	d, err := f.DWARF()
	if err != nil {
		return err
	}

	inlinedFuncsMap = make(map[uint64][]*dwarf.Entry)
	reader := d.Reader()

	for {
		entry, err := reader.Next()
		if entry == nil {
			break
		}
		if err != nil {
			return err
		}

		if entry.Tag == dwarf.TagInlinedSubroutine {
			for i := range entry.Field {
				if entry.Field[i].Attr == dwarf.AttrHighpc {
					inlinedFuncsMap[entry.Field[i].Val.(uint64)] = append(inlinedFuncsMap[entry.Field[i].Val.(uint64)], entry)
				}
			}
		}
	}

	return nil
}

func main() {

	f, err := elf.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	err = dwarfReadInlinedFunctions(os.Args[1])
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
			if event.ReturnAddrs[i] == 0 {
				break
			}

			entries, ok := inlinedFuncsMap[event.ReturnAddrs[i]]
			if ok {
				for _, entry := range entries {
					printEntry(event.ReturnAddrs[i], entry)
				}
			}

			funcName, fileName, lineNum := resolveSymbolNameFromFPOffset(event.ReturnAddrs[i])
			fmt.Printf("\t0x%x: %s (%s:%d)\n", event.ReturnAddrs[i], funcName, fileName, lineNum)
		}
	}
}

func printEntry(pc uint64, e *dwarf.Entry) {
	var (
		offset dwarf.Offset
		name   string
		file   int64
		line   int64
	)
	for i := range e.Field {
		if e.Field[i].Attr == dwarf.AttrAbstractOrigin {
			offset = e.Field[i].Val.(dwarf.Offset)
			reader.Seek(offset)
			entry, err := reader.Next()
			if err != nil {
				panic(err)
			}
			for j := range entry.Field {
				if entry.Field[j].Attr == dwarf.AttrName {
					name = entry.Field[j].Val.(string)
				}
			}
		}
		if e.Field[i].Attr == dwarf.AttrCallFile {
			file = e.Field[i].Val.(int64)
		}
		if e.Field[i].Attr == dwarf.AttrCallLine {
			line = e.Field[i].Val.(int64)
		}

	}

	fmt.Printf("\t0x%x: %s (%d:%d) INLINED\n", pc, name, file, line)
}
