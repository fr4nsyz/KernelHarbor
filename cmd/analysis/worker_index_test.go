package main

import "testing"

func TestWorkerIndexInRangeForLongHostnames(t *testing.T) {
	hosts := []string{"web-01", "kernelharbor-worker-node-3", "ubuntu-jammy-builder", "ip-10-0-12-34.ec2.internal"}
	for _, h := range hosts {
		for _, n := range []int{1, 3, 4, 8} {
			if got := workerIndex(h, n); got < 0 || got >= n {
				t.Errorf("workerIndex(%q, %d) = %d, want [0,%d)", h, n, got, n)
			}
		}
	}
}
