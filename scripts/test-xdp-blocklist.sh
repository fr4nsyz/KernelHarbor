#!/bin/bash

set -e
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_SRC="${REPO_ROOT}/bpf/xdp-blocklist.bpf.c"
WORKDIR="$(mktemp -d)"
OBJ="${WORKDIR}/xdp-blocklist.o"

NS_NAME="xdp-test"
HOST_IF="veth0"
NS_IF="veth1"
HOST_IP="10.200.0.1"
NS_IP="10.200.0.2"
PREFIX_LEN=32
BLOCKED_IP="${NS_IP}"

MAP_V4_ID=""
ATTACHED=false

cleanup() {
    set +e
    echo ""
    echo -e "${CYAN}Cleaning up...${NC}"
    if [ "${ATTACHED}" = true ]; then
        ip link set dev "${HOST_IF}" xdpgeneric off 2>/dev/null && \
            echo -e "  detached XDP from ${HOST_IF}"
    fi
    ip netns del "${NS_NAME}" 2>/dev/null && \
        echo -e "  deleted netns ${NS_NAME}"
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

print_banner() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║         KernelHarbor - XDP Blocklist Test Rig           ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

require_tools() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}✗ Must run as root (sudo ./scripts/test-xdp-blocklist.sh)${NC}"
        exit 1
    fi
    for tool in clang ip bpftool ping; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}✗ Missing tool: $tool${NC}"
            exit 1
        fi
    done
    if [ ! -f "${REPO_ROOT}/bpf/vmlinux.h" ]; then
        echo -e "${RED}✗ ${REPO_ROOT}/bpf/vmlinux.h not found.${NC}"
        echo -e "${YELLOW}  Generate it with:${NC}"
        echo -e "${YELLOW}  bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h${NC}"
        exit 1
    fi
}

compile_object() {
    echo -e "${CYAN}${BOLD}[1/5] Compiling XDP program...${NC}"
    if ! clang -O2 -g -target bpf -I "${REPO_ROOT}/bpf/" -c "${BPF_SRC}" -o "${OBJ}" 2>&1; then
        echo -e "${RED}✗ clang failed (is this an LLVM clang with the BPF backend?)${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Compiled $(basename "${OBJ}")${NC}"
}

setup_lab() {
    echo -e "${CYAN}${BOLD}[2/5] Setting up namespace lab...${NC}"
    # Inside containers /var/run/netns must be a shared bind mount for ip netns to work
    if [ -f /proc/1/.dockerenv ] || [ -f /.dockerenv ]; then
        mkdir -p /var/run/netns
        mount --bind /var/run/netns /var/run/netns
        mount --make-shared /var/run/netns
    fi
    ip netns add "${NS_NAME}"
    ip link add "${HOST_IF}" type veth peer name "${NS_IF}" netns "${NS_NAME}"
    ip addr add "${HOST_IP}/24" dev "${HOST_IF}"
    ip link set "${HOST_IF}" up
    ip -n "${NS_NAME}" addr add "${NS_IP}/24" dev "${NS_IF}"
    ip -n "${NS_NAME}" link set lo up
    ip -n "${NS_NAME}" link set "${NS_IF}" up
    ip link set "${HOST_IF}" up
    echo -e "${GREEN}✓ host ${HOST_IF}(${HOST_IP}) <-> ${NS_NAME}:${NS_IF}(${NS_IP})${NC}"
}

attach_xdp() {
    echo -e "${CYAN}${BOLD}[3/5] Attaching XDP (generic mode) to ${HOST_IF}...${NC}"
    ip link set dev "${HOST_IF}" xdpgeneric obj "${OBJ}" sec xdp
    ATTACHED=true
    ip link show "${HOST_IF}" | grep -q xdpgeneric
    echo -e "${GREEN}✓ Attached${NC}"
}

map_id_for() {
    local map_name="$1"
    bpftool map list | awk '/name '"${map_name}"'/ {gsub(":", "", $1); print $1}' | head -n 1
}

hex_key_v4() {
    # LPM key: prefixlen as LE u32, then IPv4 in network byte order
    local prefix_le
    prefix_le=$(printf '%08x' "$((PREFIX_LEN))" | sed 's/\(..\)\(..\)\(..\)\(..\)/\4 \3 \2 \1/')
    local ip_hex
    ip_hex=$(printf '%02x ' ${1//./ } )
    printf '%s %s' "${prefix_le}" "${ip_hex}"
}

seed_blocklist() {
    echo -e "${CYAN}${BOLD}[4/5] Seeding blocklist with ${BLOCKED_IP}/${PREFIX_LEN}...${NC}"
    MAP_V4_ID=$(map_id_for blocklist_v4)
    if [ -z "${MAP_V4_ID}" ]; then
        echo -e "${RED}✗ blocklist_v4 map not found${NC}"
        exit 1
    fi
    local key
    key=$(hex_key_v4 "${BLOCKED_IP}")
    bpftool map update id "${MAP_V4_ID}" key hex ${key} value hex 01 > /dev/null
    echo -e "${GREEN}✓ Inserted into map id ${MAP_V4_ID}: key hex ${key}${NC}"
}

run_ping_test() {
    echo -e "${CYAN}${BOLD}[5/5] Ping tests from inside ${NS_NAME}...${NC}"

    echo -ne "  blocked (${BLOCKED_IP}) -> expect DROP: "
    if ip netns exec "${NS_NAME}" ping -c 2 -W 1 "${HOST_IP}" > /dev/null 2>&1; then
        echo -e "${RED}FAIL (got replies)${NC}"
        return 1
    else
        echo -e "${GREEN}PASS${NC}"
    fi

    local key
    key=$(hex_key_v4 "${BLOCKED_IP}")
    bpftool map delete id "${MAP_V4_ID}" key hex ${key} > /dev/null

    echo -ne "  unblocked -> expect PASS: "
    if ip netns exec "${NS_NAME}" ping -c 2 -W 1 "${HOST_IP}" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL (no replies after delete)${NC}"
        return 1
    fi
}

main() {
    print_banner
    require_tools
    compile_object
    setup_lab
    attach_xdp
    seed_blocklist

    echo ""
    if run_ping_test; then
        echo ""
        echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗"
        echo -e "║                XDP blocklist works! ✓                   ║"
        echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
    else
        echo ""
        echo -e "${RED}${BOLD}XDP blocklist test FAILED${NC}"
        exit 1
    fi
}

main "$@"
