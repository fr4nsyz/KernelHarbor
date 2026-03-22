
Dependencies:

```
sudo dnf update -y
sudo dnf install -y \
  clang llvm \
  elfutils-libelf-devel \
  kernel-devel kernel-headers \
  libbpf-devel \
  bpftool \
  git make pkgconf \
  zlib-devel
```

go install github.com/cilium/ebpf/cmd/bpf2go@latest
go get -tool github.com/cilium/ebpf/cmd/bpf2go

sudo dnf install glibc-devel.i686

Build:

go generate

go build .

sudo ./KernelHarbor # need sudo to listen to kernel events
