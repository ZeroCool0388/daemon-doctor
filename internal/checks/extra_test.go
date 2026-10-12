package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func TestLaunchedWithFlags(t *testing.T) {
	p := plugins.Plugin{
		ID:      "example-desktop-app",
		Name:    "Example Desktop App",
		Process: plugins.ProcessMatch{Match: "Some App"},
		Checks: []plugins.Check{{
			Type:  plugins.CheckLaunchedWithFlags,
			Flags: []string{"--disable-renderer-backgrounding"},
		}},
	}
	const exe = "/Applications/Some App.app/Contents/MacOS/Some App"
	with := sysprobe.Snapshot{Processes: []sysprobe.Process{{
		PID:  42,
		PPID: 1,
		Name: "Some App",
		Exe:  exe,
		Cmd:  exe + " --disable-renderer-backgrounding",
	}}}
	without := sysprobe.Snapshot{Processes: []sysprobe.Process{{
		PID:  42,
		PPID: 1,
		Name: "Some App",
		Exe:  exe,
		Cmd:  exe,
	}}}
	runner := NewRunner(nil)
	ok, err := runner.Run(p, with)
	if err != nil || !ok[0].Healthy || ok[0].MissingFlags {
		t.Fatalf("%+v %v", ok, err)
	}
	bad, err := runner.Run(p, without)
	if err != nil {
		t.Fatal(err)
	}
	if !bad[0].MissingFlags || !strings.Contains(bad[0].Detail, "started without its required settings") {
		t.Fatalf("%+v", bad[0])
	}
}

func TestFileRecentAndLaunchdJob(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	p := plugins.Plugin{
		ID:      "example-health",
		Name:    "Example Health",
		Process: plugins.ProcessMatch{CmdContains: "example-health"},
		Checks: []plugins.Check{
			{Type: plugins.CheckLaunchdJob, Label: "com.example.health", MaxAge: "10m"},
			{Type: plugins.CheckFileRecent, Path: "/tmp/example-heartbeat", MaxAge: "5m"},
		},
	}
	if err := plugins.Validate(&p, plugins.BuiltinCosts()); err != nil {
		t.Fatal(err)
	}
	fresh := sysprobe.Snapshot{
		Launchd: map[string]sysprobe.LaunchdJob{
			"com.example.health": {ExitCode: 0, ExitKnown: true, LastRun: now.Add(-2 * time.Minute), LastRunKnown: true},
		},
		Files: map[string]sysprobe.FileStamp{
			"/tmp/example-heartbeat": {Known: true, ModTime: now.Add(-time.Minute)},
		},
	}
	runner := NewRunner(nil)
	runner.Now = func() time.Time { return now }
	got, err := runner.Run(p, fresh)
	if err != nil || !AllHealthy(got) {
		t.Fatalf("%+v %v", got, err)
	}

	stale := fresh
	stale.Launchd = map[string]sysprobe.LaunchdJob{
		"com.example.health": {ExitCode: 1, ExitKnown: true, LastRun: now.Add(-2 * time.Minute), LastRunKnown: true},
	}
	got, err = runner.Run(p, stale)
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].JobFailed || !strings.Contains(got[0].Detail, "last exited with status 1") {
		t.Fatalf("%+v", got[0])
	}
	if !got[1].Skipped {
		t.Fatalf("later check should be skipped: %+v", got[1])
	}

	oldFile := fresh
	oldFile.Files = map[string]sysprobe.FileStamp{
		"/tmp/example-heartbeat": {Known: true, ModTime: now.Add(-30 * time.Minute)},
	}
	got, err = runner.Run(p, oldFile)
	if err != nil || !got[0].Healthy || !got[1].Stuck || !strings.Contains(got[1].Detail, "has not been modified") {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestCommandContainsRunsTheProcessCheck(t *testing.T) {
	p := plugins.Plugin{
		ID:   "example-gateway",
		Name: "Example Gateway",
		Process: plugins.ProcessMatch{
			Match:       "node",
			CmdContains: "example-gateway",
		},
		Checks: []plugins.Check{{Type: plugins.CheckProcessRunning}},
	}
	snap := sysprobe.Snapshot{Processes: []sysprobe.Process{
		{PID: 3, Name: "node", Exe: "/usr/local/bin/node", Cmd: "node /opt/other-tool/server.js"},
		{PID: 8, Name: "node", Exe: "/usr/local/bin/node", Cmd: "node /opt/example-gateway/server.js"},
	}}
	got, err := NewRunner(nil).Run(p, snap)
	if err != nil || !got[0].Healthy || !strings.Contains(got[0].Detail, "pid 8") {
		t.Fatalf("%+v %v", got, err)
	}
}
