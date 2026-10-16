package doctor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func loadExample(t *testing.T) plugins.Plugin {
	t.Helper()
	p, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "example-desktop-app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func running(conns int) sysprobe.Snapshot {
	s := sysprobe.Snapshot{
		Processes: []sysprobe.Process{
			{PID: 4, PPID: 1, Name: "example-desktop-app", Exe: "example-desktop-app"},
			{PID: 5, PPID: 4, Name: "helper", Exe: "helper"},
		},
		OutboundPorts: map[int][]int{},
	}
	for i := 0; i < conns; i++ {
		s.OutboundPorts[5] = append(s.OutboundPorts[5], 443)
	}
	return s
}

func TestReplayStuckWhileProcessRemainsUp(t *testing.T) {
	// The process stays up, so the verdict is stuck rather than down.
	book, err := logbook.Open(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	src := &sysprobe.MemSource{}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	d, err := New([]plugins.Plugin{loadExample(t)}, src, nil, book, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	src.Set(running(2))
	if rows, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	} else if rows[0].Status != rules.StatusOK || len(rows[0].Alerts) != 0 {
		t.Fatalf("healthy: %+v", rows[0])
	}

	src.Set(running(0))
	for i := 1; i <= 2; i++ {
		rows, err := d.Cycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if rows[0].Status != rules.StatusWatch || len(rows[0].Alerts) != 0 {
			t.Fatalf("streak %d: status %s alerts %d", i, rows[0].Status, len(rows[0].Alerts))
		}
	}
	rows, err := d.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Status != rules.StatusStuck || len(rows[0].Alerts) != 1 {
		t.Fatalf("stuck verdict: %+v", rows[0])
	}
	if rows[0].Alerts[0].Kind != rules.KindStuck || rows[0].Alerts[0].Action != plugins.FixForceRestart {
		t.Fatalf("alert: %+v", rows[0].Alerts[0])
	}
	rows, err = d.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows[0].Alerts) != 0 {
		t.Fatalf("repeat alert: %+v", rows[0].Alerts)
	}

	events := readEvents(t, book.Path())
	alerts := 0
	checks := 0
	for _, event := range events {
		switch event.Kind {
		case "alert":
			alerts++
			if event.AlertKind != rules.KindStuck {
				t.Fatalf("alert kind %s", event.AlertKind)
			}
		case "check":
			checks++
		}
	}
	if alerts != 1 || checks != 3 {
		t.Fatalf("log alerts %d checks %d", alerts, checks)
	}
}

func TestLogRecordsStateChangesAndHourlySummary(t *testing.T) {
	book, err := logbook.Open(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	src := &sysprobe.MemSource{}
	src.Set(running(2))
	d, err := New([]plugins.Plugin{loadExample(t)}, src, nil, book, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := d.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	checks, summaries := countKinds(t, book.Path())
	if checks != 1 || summaries != 0 {
		t.Fatalf("before the hour: checks %d summaries %d", checks, summaries)
	}
	now = now.Add(time.Hour)
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	checks, summaries = countKinds(t, book.Path())
	if checks != 1 || summaries != 1 {
		t.Fatalf("after the hour: checks %d summaries %d", checks, summaries)
	}
	var summary string
	for _, event := range readEvents(t, book.Path()) {
		if event.Kind == "summary" {
			summary = event.Message
		}
	}
	if summary != "Hourly summary. Example Desktop App: ok." {
		t.Fatalf("summary %q", summary)
	}
}

func countKinds(t *testing.T, path string) (checks, summaries int) {
	t.Helper()
	for _, event := range readEvents(t, path) {
		switch event.Kind {
		case "check":
			checks++
		case "summary":
			summaries++
		}
	}
	return checks, summaries
}

func TestDryRunFixIsLoggedAndUnknownFixIsRefused(t *testing.T) {
	book, err := logbook.Open(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	src := &sysprobe.MemSource{}
	src.Set(running(0))
	d, err := New([]plugins.Plugin{loadExample(t)}, src, nil, book, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.ApplyFix(context.Background(), "example-desktop-app", plugins.FixForceRestart, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fixed || res.Message == "" {
		t.Fatalf("result: %+v", res)
	}
	if _, err := d.ApplyFix(context.Background(), "example-desktop-app", "echo hello", false); err == nil {
		t.Fatal("expected an unknown fix to be refused")
	}
	sawFix := false
	sawRefusal := false
	for _, event := range readEvents(t, book.Path()) {
		if event.Kind != "fix" {
			continue
		}
		if event.DryRun != nil && *event.DryRun {
			sawFix = true
		}
		if event.Message == `unknown fix "echo hello"` {
			sawRefusal = true
		}
	}
	if !sawFix || !sawRefusal {
		t.Fatalf("fix log missing dry-run=%v refusal=%v", sawFix, sawRefusal)
	}
}

func TestRunStopsWhenCancelled(t *testing.T) {
	src := &sysprobe.MemSource{}
	src.Set(running(1))
	d, err := New([]plugins.Plugin{loadExample(t)}, src, nil, nil, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- d.Run(ctx, time.Hour, func([]ServiceStatus) {
			select {
			case <-started:
			default:
				close(started)
			}
			cancel()
		}, func(err error) {
			t.Errorf("cycle: %v", err)
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not check")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestNetworkDownPausesServiceChecks(t *testing.T) {
	host := plugins.Plugin{
		ID:   "this-mac",
		Name: "This Mac",
		Host: true,
		Checks: []plugins.Check{
			{Type: plugins.CheckSleep},
			{Type: plugins.CheckNetwork},
			{Type: plugins.CheckDisk, MinFreePercent: 10},
		},
	}
	service := loadExample(t)
	src := &sysprobe.MemSource{}
	now := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	d, err := New([]plugins.Plugin{host, service}, src, nil, nil, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	up := running(0)
	up.Host = sysprobe.Host{SleepKnown: true, NetworkKnown: true, NetworkUp: true, DiskKnown: true, DiskFreePercent: 40}
	src.Set(up)
	rows, err := d.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[1].Status != rules.StatusWatch || len(rows[1].Alerts) != 0 {
		t.Fatalf("first miss: %+v", rows[1])
	}

	down := up
	down.Host.NetworkUp = false
	src.Set(down)
	for i := 0; i < 2; i++ {
		rows, err = d.Cycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if rows[0].Status != rules.StatusHeld || rows[1].Status != rules.StatusHeld {
			t.Fatalf("held: %+v %+v", rows[0].Status, rows[1].Status)
		}
		if len(rows[1].Alerts) != 0 {
			t.Fatalf("service alert while paused: %+v", rows[1].Alerts)
		}
	}
	if len(rows[0].Alerts) != 0 {
		t.Fatalf("repeat network alert: %+v", rows[0].Alerts)
	}

	src.Set(up)
	rows, err = d.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[1].Status != rules.StatusWatch {
		t.Fatalf("streak should still be short: %+v", rows[1])
	}
	var summary string
	for _, alert := range rows[0].Alerts {
		if alert.Kind == rules.KindNetworkBack {
			summary = alert.Message
		}
	}
	if summary == "" || !bytes.Contains([]byte(summary), []byte("services healthy")) {
		t.Fatalf("summary: %q alerts %+v", summary, rows[0].Alerts)
	}
	rows, err = d.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[1].Status != rules.StatusStuck || len(rows[1].Alerts) != 1 {
		t.Fatalf("third running sample should be stuck: %+v", rows[1])
	}
}

func TestUnwatchedStopIsLimitedToTheNamedProcess(t *testing.T) {
	host := plugins.Plugin{
		ID:   "this-mac",
		Name: "This Mac",
		Host: true,
		Checks: []plugins.Check{
			{Type: plugins.CheckNetwork},
			{Type: plugins.CheckCPU, CPUPercent: 85, Duration: "5m"},
		},
	}
	service := loadExample(t)
	src := &sysprobe.MemSource{}
	clock := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	d, err := New([]plugins.Plugin{host, service}, src, nil, nil, nil, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	snap := running(1)
	snap.Host = sysprobe.Host{NetworkKnown: true, NetworkUp: true}
	snap.Processes = append(snap.Processes, sysprobe.Process{PID: 9, PPID: 1, Name: "ExampleTool", CPUKnown: true, CPUPercent: 95})
	src.Set(snap)
	if _, err := d.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(5 * time.Minute)
	rows, err := d.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, alert := range rows[0].Alerts {
		if alert.Kind == rules.KindCPUHog && alert.Process == "ExampleTool" && alert.OfferFix {
			found = true
		}
	}
	if !found {
		t.Fatalf("alerts: %+v", rows[0].Alerts)
	}
	if _, err := d.ApplyStop(context.Background(), "other-tool", true); err == nil {
		t.Fatal("unnamed process should be refused")
	}
	res, err := d.ApplyStop(context.Background(), "ExampleTool", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Message, "Dry run") {
		t.Fatalf("message %q", res.Message)
	}
}

func readEvents(t *testing.T, path string) []logbook.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []logbook.Event
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var event logbook.Event
		if err := json.Unmarshal(sc.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		out = append(out, event)
	}
	return out
}
