GO := go

EVENT_ID_MAIN_SRC := $(abspath ./cmd/event_id/event_id.go)
EVENT_ID_BPF_SRC := $(abspath ./cmd/event_id/event_id.c)

UID_MAIN_SRC := $(abspath ./cmd/uid_filter/uid_filter.go)
UID_BPF_SRC := $(abspath ./cmd/uid_filter/uid_filter.c)

MULTIPLE_MAIN_SRC := $(abspath ./cmd/multiple_filter/multiple_filter.go)
MULTIPLE_BPF_SRC := $(abspath ./cmd/multiple_filter/multiple_filter.c)

OUTPUT := $(abspath ./dist)

all: $(OUTPUT)/event_id $(OUTPUT)/uid_filter $(OUTPUT)/multiple_filter

$(OUTPUT)/event_id: $(EVENT_ID_BPF_SRC) $(EVENT_ID_MAIN_SRC) $(OUTPUT)
	$(GO) generate $(EVENT_ID_MAIN_SRC)
	$(GO) build -o $@ ./cmd/event_id/*.go

$(OUTPUT)/uid_filter: $(UID_BPF_SRC) $(UID_MAIN_SRC) $(OUTPUT)
	$(GO) generate $(UID_MAIN_SRC)
	$(GO) build -o $@ ./cmd/uid_filter/*.go

$(OUTPUT)/multiple_filter: $(MULTIPLE_BPF_SRC) $(MULTIPLE_MAIN_SRC) $(OUTPUT)
	$(GO) generate $(MULTIPLE_MAIN_SRC)
	$(GO) build -o $@ ./cmd/multiple_filter/*.go

.PHONY: clean
clean:
	$(GO) clean
	rm -rf $(OUTPUT)/* *.o