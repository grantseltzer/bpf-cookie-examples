GO := go

EVENT_ID_MAIN_SRC := $(abspath ./cmd/event_id/event_id.go)
EVENT_ID_BPF_SRC := $(abspath ./cmd/event_id/event_id.c)

OUTPUT := $(abspath ./dist)

all: $(OUTPUT)/event_id

$(OUTPUT)/event_id: $(EVENT_ID_BPF_SRC) $(EVENT_ID_MAIN_SRC) $(OUTPUT)
	$(GO) generate $(EVENT_ID_MAIN_SRC)
	$(GO) build -o $@ ./cmd/event_id/*.go

.PHONY: clean
clean:
	$(GO) clean
	rm -rf $(OUTPUT)/* *.o