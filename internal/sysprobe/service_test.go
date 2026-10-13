package sysprobe

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReadSystemServices(t *testing.T) {
	const missing = "printf 'Could not find service com.apple.screensharing in domain for system\n' >&2\nexit 113\n"
	for _, tc := range []struct {
		name      string
		launchctl string
		lsof      string
		want      ServiceState
	}{
		{name: "loaded but never started", launchctl: "printf 'system/com.apple.screensharing = {\n state = not running\n runs = 0\n}\n'\n", lsof: "exit 2\n", want: ServiceState{Loaded: true, Known: true}},
		{name: "disabled and not listening", launchctl: missing, lsof: "exit 1\n", want: ServiceState{Known: true}},
		{name: "IPv4 listener fallback", launchctl: missing, lsof: "printf 'p1\nf5\nn*:5900\n'\n", want: ServiceState{Listening: true, Known: true}},
		{name: "IPv6 listener fallback", launchctl: missing, lsof: "printf 'p1\nf5\nn[::1]:5900\n'\n", want: ServiceState{Listening: true, Known: true}},
		{name: "wrong port does not count", launchctl: missing, lsof: "printf 'n*:5901\n'\n", want: ServiceState{Known: true}},
		{name: "established connection does not count", launchctl: missing, lsof: "printf 'n127.0.0.1:50000->127.0.0.1:5900\n'\n", want: ServiceState{Known: true}},
		{name: "permission denied is unknown", launchctl: "printf 'Operation not permitted\n' >&2\nexit 1\n", lsof: "exit 1\n"},
		{name: "listener despite unreadable launchd", launchctl: "exit 1\n", lsof: "printf 'n127.0.0.1:5900\n'\n", want: ServiceState{Listening: true, Known: true}},
		{name: "socket read error is unknown", launchctl: missing, lsof: "printf 'cannot read sockets\n' >&2\nexit 1\n"},
		{name: "missing probe commands is unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.launchctl != "" {
				// Check the system domain, not the GUI domain used for jobs.
				body := "[ \"$*\" = 'print system/com.apple.screensharing' ] || exit 2\n" + tc.launchctl
				writeProbeCommand(t, dir, "launchctl", body)
			}
			if tc.lsof != "" {
				body := "[ \"$*\" = '-nP -a -iTCP:5900 -sTCP:LISTEN -F n' ] || exit 2\n" + tc.lsof
				writeProbeCommand(t, dir, "lsof", body)
			}
			t.Setenv("PATH", dir)
			got := readSystemServices(context.Background(), []ServiceHint{{Label: "com.apple.screensharing", Port: 5900}})
			if got["com.apple.screensharing"] != tc.want {
				t.Fatalf("state %+v, want %+v", got, tc.want)
			}
		})
	}
}

func writeProbeCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestCancelledServiceProbeIsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := readSystemServices(ctx, []ServiceHint{{Label: "com.apple.screensharing", Port: 5900}})
	if got["com.apple.screensharing"] != (ServiceState{}) {
		t.Fatalf("cancelled probe: %+v", got)
	}
}

func TestServiceSnapshotsAreCopied(t *testing.T) {
	source := &MemSource{Current: Snapshot{Services: map[string]ServiceState{"example": {Loaded: true, Known: true}}}}
	snap, err := source.Take(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snap.Services["example"] = ServiceState{}
	if !source.Current.Services["example"].Loaded {
		t.Fatal("editing a snapshot changed the source")
	}
}
