package main

import "testing"

func TestIptablesAddrFlagMatchesRemotePeer(t *testing.T) {
	for chain, want := range map[string]string{"OUTPUT": "-d", "INPUT": "-s"} {
		if got := iptablesAddrFlag(chain); got != want {
			t.Errorf("iptablesAddrFlag(%q) = %q, want %q", chain, got, want)
		}
	}
}
