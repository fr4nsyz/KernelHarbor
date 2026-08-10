TRACERS  := execve-tracer open-tracer openat-tracer
APPS     := agent analysis

VMLINUX  := bpf/vmlinux.h
BPF_HDRS := $(wildcard bpf/*.h)

PROTO_GEN := .proto-gen

.PHONY: all build test clean proto $(TRACERS) $(APPS)

all: build
build: $(TRACERS) $(APPS)

# --- proto ---
# Regenerates cmd/agent/proto (package proto) and cmd/analysis/pb (package pb)
# from proto/agent.proto. protoc-gen-go writes under the go_package path
# (kernelharbor/proto/kernelharborpb), so copy the output to both modules and
# rewrite the package clause to match each module's import path.
proto:
	rm -rf $(PROTO_GEN)
	mkdir -p $(PROTO_GEN)
	protoc --go_out=$(PROTO_GEN) --go-grpc_out=$(PROTO_GEN) proto/agent.proto
	mkdir -p cmd/agent/proto cmd/analysis/pb
	cp $(PROTO_GEN)/kernelharbor/proto/kernelharborpb/agent.pb.go $(PROTO_GEN)/kernelharbor/proto/kernelharborpb/agent_grpc.pb.go cmd/agent/proto/
	cp $(PROTO_GEN)/kernelharbor/proto/kernelharborpb/agent.pb.go $(PROTO_GEN)/kernelharbor/proto/kernelharborpb/agent_grpc.pb.go cmd/analysis/pb/
	sed -i 's/package kernelharborpb/package proto/' cmd/agent/proto/*.go
	sed -i 's/package kernelharborpb/package pb/' cmd/analysis/pb/*.go
	rm -rf $(PROTO_GEN)

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# --- tracers ---
# bpf2go's generated-file prefix is the lowercased identifier with no dashes,
# which matches the dir name minus dashes for every current tracer.
define TRACER_RULES
$(1)_IDENT  := $(subst -,,$(1))
$(1)_BIN    := cmd/$(1)/$(1)
$(1)_BPF    := bpf/$(1).bpf.c
$(1)_GENGO  := cmd/$(1)/$$($(1)_IDENT)_bpfel.go cmd/$(1)/$$($(1)_IDENT)_bpfeb.go
$(1)_GENOBJ := cmd/$(1)/$$($(1)_IDENT)_bpfel.o  cmd/$(1)/$$($(1)_IDENT)_bpfeb.o

$$($(1)_GENGO) $$($(1)_GENOBJ) &: $$($(1)_BPF) $(BPF_HDRS) $(VMLINUX) cmd/$(1)/gen.go
	cd cmd/$(1) && go generate ./...

$$($(1)_BIN): $$($(1)_GENGO) $$($(1)_GENOBJ) $$(wildcard cmd/$(1)/*.go)
	cd cmd/$(1) && go build -o $(1) .

$(1): $$($(1)_BIN)
endef

$(foreach t,$(TRACERS),$(eval $(call TRACER_RULES,$(t))))

# --- agent ---
# AGENT_BPF and AGENT_GENGO must stay in sync with the //go:generate directives
# in cmd/agent/gen.go.
AGENT_BIN    := cmd/agent/agent
AGENT_BPF    := bpf/execve-tracer.bpf.c bpf/open-tracer.bpf.c \
                bpf/connect-tracer.bpf.c bpf/openat-tracer.bpf.c
AGENT_GENGO  := cmd/agent/execvetracer_bpfel.go cmd/agent/opentracer_bpfel.go \
                cmd/agent/connecttracer_bpfel.go cmd/agent/openattracer_bpfel.go
AGENT_GENOBJ := $(AGENT_GENGO:.go=.o)
AGENT_SRC    := $(wildcard cmd/agent/*.go) $(wildcard cmd/agent/proto/*.go)

$(AGENT_GENGO) $(AGENT_GENOBJ) &: $(AGENT_BPF) $(BPF_HDRS) $(VMLINUX) cmd/agent/gen.go
	cd cmd/agent && go generate ./...

$(AGENT_BIN): $(AGENT_GENGO) $(AGENT_GENOBJ) $(AGENT_SRC)
	cd cmd/agent && go build -o agent .

agent: $(AGENT_BIN)

# --- analysis ---
ANALYSIS_BIN := cmd/analysis/analysis

$(ANALYSIS_BIN): $(wildcard cmd/analysis/*.go) $(wildcard cmd/analysis/pb/*.go)
	cd cmd/analysis && go build -o analysis .

analysis: $(ANALYSIS_BIN)

# --- test ---
test:
	cd cmd/analysis && go test ./...
	cd cmd/agent && go test ./...

# --- clean ---
ALL_BIN_PATHS := $(foreach b,$(TRACERS) $(APPS),cmd/$(b)/$(b))

clean:
	rm -f $(ALL_BIN_PATHS)
	rm -f $(wildcard cmd/*/*_bpf*.go) $(wildcard cmd/*/*_bpf*.o)
	rm -f $(VMLINUX)
