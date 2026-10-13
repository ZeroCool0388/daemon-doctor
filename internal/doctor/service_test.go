package doctor

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func TestScreenSharingIdleFailureAndRecovery(t *testing.T) {
	p, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "screen-sharing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	hints := hintsFor([]plugins.Plugin{p})
	if len(hints.Services) != 1 || hints.Services[0].Label != "com.apple.screensharing" || hints.Services[0].Port != 5900 || len(hints.Labels) != 0 {
		t.Fatalf("wrong probe hints: %+v", hints)
	}
	src := &sysprobe.MemSource{}
	d, err := New([]plugins.Plugin{p}, src, nil, nil, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		state  sysprobe.ServiceState
		status string
		alerts int
	}{
		{name: "idle enabled", state: sysprobe.ServiceState{Loaded: true, Known: true}, status: rules.StatusOK},
		{name: "still idle enabled", state: sysprobe.ServiceState{Loaded: true, Known: true}, status: rules.StatusOK},
		{name: "listener only", state: sysprobe.ServiceState{Listening: true, Known: true}, status: rules.StatusOK},
		{name: "unknown probe", status: rules.StatusWatch},
		{name: "first unavailable sample", state: sysprobe.ServiceState{Known: true}, status: rules.StatusPending},
		{name: "confirmed unavailable", state: sysprobe.ServiceState{Known: true}, status: rules.StatusDown, alerts: 1},
		{name: "unchanged unavailable", state: sysprobe.ServiceState{Known: true}, status: rules.StatusDown},
		{name: "idle recovery", state: sysprobe.ServiceState{Loaded: true, Known: true}, status: rules.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src.Set(sysprobe.Snapshot{Services: map[string]sysprobe.ServiceState{"com.apple.screensharing": tc.state}})
			rows, err := d.Cycle(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].Status != tc.status || len(rows[0].Alerts) != tc.alerts {
				t.Fatalf("unexpected status: %+v", rows)
			}
			if tc.alerts > 0 && (rows[0].Alerts[0].Kind != rules.KindDown || !strings.Contains(rows[0].Alerts[0].Message, "disabled or unreachable")) {
				t.Fatalf("unexpected alert: %+v", rows[0].Alerts)
			}
		})
	}
}
