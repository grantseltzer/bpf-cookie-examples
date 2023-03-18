GO := go
USERTRACE_SRC := $(abspath ./cmd/usertrace/*.go)
BPF_SRC := $(abspath ./pkg/bpf/uprobe.bpf.c)
SAMPLE_SRC := $(abspath ./cmd/sample_program/main.go)
OUTPUT := $(abspath ./dist)

all: $(OUTPUT)/usertrace $(OUTPUT)/sample

$(OUTPUT)/usertrace: $(BPF_SRC) $(USERTRACE_SRC) $(OUTPUT)
	$(GO) generate $(USERTRACE_SRC)
	$(GO) build -o $@ $(USERTRACE_SRC)

$(OUTPUT)/sample: $(SAMPLE_SRC)
	$(GO) build -o $@ $(SAMPLE_SRC)

.PHONY: clean
clean:
	$(GO) clean
	rm -rf $(OUTPUT)/* *.o