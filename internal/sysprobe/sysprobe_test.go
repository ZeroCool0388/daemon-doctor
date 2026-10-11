package sysprobe

import (
	"testing"
)

func TestMatchIsExact(t *testing.T) {
	proc := Process{
		PID:  4,
		Name: "example-desktop",
		Exe:  "/Applications/Example.app/Contents/MacOS/example-desktop-app",
		Cmd:  "/Applications/Example.app/Contents/MacOS/example-desktop-app --flag",
	}
	if !Matches(proc, "example-desktop-app") {
		t.Fatal("base name should match")
	}
	if !Matches(proc, proc.Exe) {
		t.Fatal("full executable should match")
	}
	if Matches(proc, "example") || Matches(proc, "desktop-app") || Matches(proc, "") {
		t.Fatal("partial names should not match")
	}
}

func TestSignalOrderChildrenFirst(t *testing.T) {
	snap := Snapshot{Processes: []Process{
		{PID: 1, PPID: 0, Name: "example-desktop-app", Exe: "example-desktop-app"},
		{PID: 2, PPID: 1, Name: "helper", Exe: "helper"},
		{PID: 3, PPID: 2, Name: "worker", Exe: "worker"},
		{PID: 9, PPID: 1, Name: "other", Exe: "other"},
	}}
	got := SignalOrder(snap, []int{1})
	want := []int{3, 2, 9, 1}
	if len(got) != len(want) {
		t.Fatalf("order %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v want %v", got, want)
		}
	}
	again := SignalOrder(snap, []int{2, 1})
	if len(again) != len(want) {
		t.Fatalf("overlapping roots visited twice: %v", again)
	}
}

func TestCountOutboundUsesTheTree(t *testing.T) {
	snap := Snapshot{
		Processes: []Process{
			{PID: 1, PPID: 0, Name: "example-desktop-app", Exe: "example-desktop-app"},
			{PID: 2, PPID: 1, Name: "helper", Exe: "helper"},
			{PID: 8, PPID: 0, Name: "other-app", Exe: "other-app"},
		},
		OutboundPorts: map[int][]int{
			1: {443, 80},
			2: {443},
			8: {443, 443},
		},
	}
	if n := CountOutbound(snap, RootPIDs(snap, "example-desktop-app"), 443); n != 2 {
		t.Fatalf("tree count = %d, want 2", n)
	}
	if n := CountOutbound(snap, RootPIDs(snap, "other-app"), 443); n != 2 {
		t.Fatalf("other count = %d, want 2", n)
	}
	if n := CountOutbound(snap, RootPIDs(snap, "missing"), 443); n != 0 {
		t.Fatalf("missing count = %d, want 0", n)
	}
}

func TestParsePSAndLsof(t *testing.T) {
	procs, err := ParsePS("  10  1 /opt/example-desktop-app --flag\n  11 10 helper\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 2 || procs[0].PID != 10 || procs[0].PPID != 1 || procs[0].Exe != "/opt/example-desktop-app --flag" {
		t.Fatalf("ps parse: %+v", procs)
	}
	// peer.test is a fictional name. 2001:db8::/32 is the documentation prefix.
	text := "" +
		"p10\n" +
		"napp.test:40000->peer.test:443\n" +
		"p10\n" +
		"napp.test:40001->peer.test:80\n" +
		"p10\n" +
		"n*:443\n" +
		"p11\n" +
		"n[2001:db8::10]:40000->[2001:db8::20]:443\n"
	ports := ParseLsofF(text)
	if len(ports[10]) != 2 || ports[10][0] != 443 || ports[10][1] != 80 {
		t.Fatalf("pid 10 ports: %v", ports[10])
	}
	if len(ports[11]) != 1 || ports[11][0] != 443 {
		t.Fatalf("pid 11 ports: %v", ports[11])
	}
}
