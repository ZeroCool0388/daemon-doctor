package checks

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func TestScreenSharingChecksAvailabilityWithoutRequiringAViewer(t *testing.T) {
	p, err := plugins.LoadFile(filepath.Join("..", "..", "plugins", "screen-sharing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		state   sysprobe.ServiceState
		process bool
		healthy bool
		down    bool
		skipped bool
		detail  string
	}{
		{name: "enabled with no viewer", state: sysprobe.ServiceState{Loaded: true, Known: true}, healthy: true, detail: "starts on demand"},
		{name: "active viewer", state: sysprobe.ServiceState{Loaded: true, Known: true}, process: true, healthy: true, detail: "is loaded"},
		{name: "listener with no viewer", state: sysprobe.ServiceState{Listening: true, Known: true}, healthy: true, detail: "5900 is listening"},
		{name: "disabled", state: sysprobe.ServiceState{Known: true}, down: true, detail: "disabled or unreachable"},
		{name: "process present but service unreachable", state: sysprobe.ServiceState{Known: true}, process: true, down: true, detail: "disabled or unreachable"},
		{name: "probe unavailable", skipped: true, detail: "could not be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := sysprobe.Snapshot{Services: map[sysprobe.ServiceHint]sysprobe.ServiceState{{Label: "com.apple.screensharing", Port: 5900}: tc.state}}
			if tc.process {
				snap.Processes = []sysprobe.Process{{PID: 42, Name: "screensharingd"}}
			}
			out, err := NewRunner(nil).Run(p, snap)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || AllHealthy(out) != tc.healthy || out[0].Failed != tc.down || out[0].NotRunning != tc.down || out[0].Skipped != tc.skipped || !strings.Contains(out[0].Detail, tc.detail) {
				t.Fatalf("unexpected outcome: %+v", out)
			}
		})
	}
}

func TestServiceChecksUseTheConfiguredPortForASharedLabel(t *testing.T) {
	const label = "com.example.shared"
	snap := sysprobe.Snapshot{Services: map[sysprobe.ServiceHint]sysprobe.ServiceState{
		{Label: label, Port: 5900}: {Listening: true, Known: true},
		{Label: label, Port: 5901}: {Known: true},
	}}
	runner := NewRunner(nil)
	for _, tc := range []struct {
		id      string
		port    int
		healthy bool
	}{
		{id: "available-service", port: 5900, healthy: true},
		{id: "unavailable-service", port: 5901},
	} {
		p := plugins.Plugin{ID: tc.id, Name: tc.id, Checks: []plugins.Check{{Type: plugins.CheckLaunchdService, Label: label, Port: tc.port}}}
		out, err := runner.Run(p, snap)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || AllHealthy(out) != tc.healthy || out[0].NotRunning == tc.healthy || out[0].Failed == tc.healthy {
			t.Fatalf("port %d: unexpected outcome %+v", tc.port, out)
		}
	}
}
