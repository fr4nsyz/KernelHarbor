package main

import (
	"net"
	"testing"
)

func TestParseXDPInterfaces(t *testing.T) {
	tests := []struct {
		spec string
		want []string
	}{
		{"", nil},
		{",", nil},
		{"eth0", []string{"eth0"}},
		{"eth0,eth1", []string{"eth0", "eth1"}},
		{" eth0 , eth1 ,,ens5", []string{"eth0", "eth1", "ens5"}},
	}
	for _, tt := range tests {
		got := parseXDPInterfaces(tt.spec)
		if len(got) != len(tt.want) {
			t.Errorf("parseXDPInterfaces(%q) = %v, want %v", tt.spec, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseXDPInterfaces(%q)[%d] = %q, want %q", tt.spec, i, got[i], tt.want[i])
			}
		}
	}
}

func TestNewLPMKeyV4(t *testing.T) {
	k := newLPMKeyV4(net.ParseIP("10.200.0.2"))
	if k.PrefixLen != 32 {
		t.Errorf("PrefixLen = %d, want 32", k.PrefixLen)
	}
	want := [4]byte{10, 200, 0, 2}
	if k.Data != want {
		t.Errorf("Data = %v, want %v (network byte order)", k.Data, want)
	}
}

func TestNewLPMKeyV6(t *testing.T) {
	k := newLPMKeyV6(net.ParseIP("2001:db8::1"))
	if k.PrefixLen != 128 {
		t.Errorf("PrefixLen = %d, want 128", k.PrefixLen)
	}
	ip := net.ParseIP("2001:db8::1").To16()
	var want [16]byte
	copy(want[:], ip)
	if k.Data != want {
		t.Errorf("Data = %v, want %v (network byte order)", k.Data, want)
	}
}

func TestNewLPMKeyV4RejectsMappedV6FormIsStillV4Bytes(t *testing.T) {
	k := newLPMKeyV4(net.ParseIP("::ffff:192.168.1.9"))
	want := [4]byte{192, 168, 1, 9}
	if k.Data != want {
		t.Errorf("Data = %v, want %v", k.Data, want)
	}
}

func TestBlockInXDPNoopWhenNotLoaded(t *testing.T) {
	if xdpLoaded.Load() {
		t.Skip("xdp unexpectedly loaded in test env")
	}
	blockInXDP("not-an-ip")
	blockInXDP("203.0.113.7")
}
