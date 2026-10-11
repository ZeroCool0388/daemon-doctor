package doctor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	if alerts != 1 || checks != 5 {
		t.Fatalf("log alerts %d checks %d", alerts, checks)
	}
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
