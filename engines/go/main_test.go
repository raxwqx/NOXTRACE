package main

import "testing"

func TestParsePorts(t *testing.T) {
	ports, err := parsePorts("80,22,80,8000-8002")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 80, 8000, 8001, 8002}
	if len(ports) != len(want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v, want %v", ports, want)
		}
	}
}

func TestParsePortsRejectsTooMany(t *testing.T) {
	if _, err := parsePorts("1-257"); err == nil {
		t.Fatal("expected large range to be rejected")
	}
}

func TestParsePortsRejectsBadPort(t *testing.T) {
	if _, err := parsePorts("0,80"); err == nil {
		t.Fatal("expected invalid port to be rejected")
	}
}
