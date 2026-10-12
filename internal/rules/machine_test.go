package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func macPlugin() plugins.Plugin {
	return plugins.Plugin{
		ID:   "this-mac",
		Name: "This Mac",
		Host: true,
		Checks: []plugins.Check{
			{Type: plugins.CheckSleep},
			{Type: plugins.CheckNetwork},
			{Type: plugins.CheckDisk, MinFreePercent: 10},
			{Type: plugins.CheckMemory, Level: "warn", Duration: "5m"},
			{Type: plugins.CheckCPU, CPUPercent: 85, Duration: "5m"},
		},
	}
}

func codexPlugin() plugins.Plugin {
	return plugins.Plugin{
		ID:      "codex",
		Name:    "Codex",
		Process: plugins.ProcessMatch{Match: "codex"},
		Checks:  []plugins.Check{{Type: plugins.CheckProcessRunning}},
		Fixes: map[string]plugins.Fix{
			plugins.FixStop:         {Kind: plugins.FixStop},
			plugins.FixRestart:      {Kind: plugins.FixRestart},
			plugins.FixForceRestart: {Kind: plugins.FixForceRestart},
		},
	}
}

func healthyOutcomes() []checks.Outcome {
	return []checks.Outcome{{Type: plugins.CheckProcessRunning, Healthy: true}}
}

func hostSnap(asleep, networkUp bool, free float64, pressure string, procs ...sysprobe.Process) sysprobe.Snapshot {
	return sysprobe.Snapshot{
		Host: sysprobe.Host{
			SleepKnown:          true,
			Asleep:              asleep,
			NetworkKnown:        true,
			NetworkUp:           networkUp,
			DiskKnown:           true,
			DiskFreePercent:     free,
			MemoryPressureKnown: true,
			MemoryPressure:      pressure,
		},
		Processes: procs,
	}
}

func samples(host plugins.Plugin, extra ...Sample) []Sample {
	out := []Sample{{Plugin: host, Outcomes: []checks.Outcome{
		{Type: plugins.CheckSleep, Healthy: true},
		{Type: plugins.CheckNetwork, Healthy: true},
		{Type: plugins.CheckDisk, Healthy: true},
		{Type: plugins.CheckMemory, Healthy: true},
		{Type: plugins.CheckCPU, Healthy: true},
	}}}
	return append(out, extra...)
}

func TestDefaultServiceMessagesStayExact(t *testing.T) {
	p := plugins.Plugin{Name: "Example Desktop App"}
	if got := message(p, KindDown); got != "Example Desktop App has stopped. It is not running." {
		t.Fatal(got)
	}
	if got := message(p, KindStuck); got != "Example Desktop App is running but its health check is failing." {
		t.Fatal(got)
	}
	if got := message(p, KindKeepsHappening); got != "Example Desktop App has failed 3 times in the last hour. Automatic fixes are paused." {
		t.Fatal(got)
	}
}

func TestEveryDefaultTemplateFills(t *testing.T) {
	fields := map[string]string{
		"name": "Codex", "process": "ExampleTool", "percent": "90",
		"duration": "5 minutes", "level": "warning", "free": "9.5",
		"time": "21:02 UTC", "ok": "2", "total": "3",
	}
	for _, kind := range []string{
		KindDown, KindStuck, KindMissingFlags, KindLaunchd, KindKeepsHappening, KindSleep, KindWake,
		KindNetworkDown, KindNetworkBack, KindDiskLow, KindCPUHog, KindMemoryHog,
		KindCPUHog + "_unwatched", KindMemoryHog + "_unwatched",
	} {
		got := fill(defaultTemplate(kind), fields)
		if got == "" || strings.Contains(got, "{") {
			t.Fatalf("%s: %q", kind, got)
		}
	}
}

func TestSleepAndNetworkHold(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 2, 0, 0, time.UTC)
	eng := NewEngine(func() time.Time { return start })
	host := macPlugin()
	awake := hostSnap(false, true, 40, "normal")
	if got := eng.DecideMachine(start, awake, samples(host)); got.Hold || len(got.Alerts) != 0 {
		t.Fatalf("awake and online: %+v", got)
	}

	asleep := hostSnap(true, true, 40, "normal")
	got := eng.DecideMachine(start, asleep, samples(host))
	if !got.Hold || len(got.Alerts) != 1 || got.Alerts[0].Kind != KindSleep {
		t.Fatalf("first sleep: %+v", got)
	}
	if got.Alerts[0].Message != "The Mac went to sleep." {
		t.Fatal(got.Alerts[0].Message)
	}
	again := eng.DecideMachine(start.Add(time.Minute), asleep, samples(host))
	if !again.Hold || len(again.Alerts) != 0 {
		t.Fatalf("repeat sleep: %+v", again)
	}
	woke := eng.DecideMachine(start.Add(2*time.Minute), awake, samples(host))
	if woke.Hold || len(woke.Alerts) != 1 || woke.Alerts[0].Kind != KindWake {
		t.Fatalf("wake: %+v", woke)
	}

	downAt := start.Add(3 * time.Minute)
	down := eng.DecideMachine(downAt, hostSnap(false, false, 40, "normal"), samples(host))
	if !down.Hold || len(down.Alerts) != 1 || down.Alerts[0].Kind != KindNetworkDown {
		t.Fatalf("network down: %+v", down)
	}
	if down.Alerts[0].Message != "The Mac lost its network connection at 21:05 UTC. Other alerts are paused until it is back." {
		t.Fatal(down.Alerts[0].Message)
	}
	quiet := eng.DecideMachine(downAt.Add(time.Minute), hostSnap(false, false, 40, "normal"), samples(host))
	if !quiet.Hold || len(quiet.Alerts) != 0 {
		t.Fatalf("repeat network: %+v", quiet)
	}

	backAt := downAt.Add(2 * time.Minute)
	backSamples := samples(host,
		Sample{Plugin: plugins.Plugin{ID: "codex", Name: "Codex"}, Outcomes: healthyOutcomes()},
		Sample{Plugin: plugins.Plugin{ID: "syncthing", Name: "Syncthing"}, Outcomes: []checks.Outcome{{Healthy: false}}},
	)
	back := eng.DecideMachine(backAt, hostSnap(false, true, 40, "normal"), backSamples)
	if back.Hold || len(back.Alerts) != 1 || back.Alerts[0].Kind != KindNetworkBack {
		t.Fatalf("network back: %+v", back)
	}
	if back.Alerts[0].Message != "The network is back at 21:07 UTC. 2 of 3 services look healthy. Needs a look: Syncthing." {
		t.Fatal(back.Alerts[0].Message)
	}
}

func TestNetworkSummaryWaitsUntilAwake(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	down := eng.DecideMachine(start, hostSnap(false, false, 40, "normal"), samples(host))
	if len(down.Alerts) != 1 || down.Alerts[0].Kind != KindNetworkDown {
		t.Fatalf("down: %+v", down)
	}
	asleep := eng.DecideMachine(start.Add(time.Minute), hostSnap(true, true, 40, "normal"), samples(host))
	if !asleep.Hold || len(asleep.Alerts) != 1 || asleep.Alerts[0].Kind != KindSleep {
		t.Fatalf("asleep while network returns: %+v", asleep)
	}
	awake := eng.DecideMachine(start.Add(2*time.Minute), hostSnap(false, true, 40, "normal"), samples(host))
	if awake.Hold || len(awake.Alerts) != 2 {
		t.Fatalf("wake: %+v", awake)
	}
	if awake.Alerts[0].Kind != KindWake || awake.Alerts[1].Kind != KindNetworkBack {
		t.Fatalf("order: %+v", awake.Alerts)
	}
	if strings.Contains(awake.Alerts[1].Message, "Needs a look") {
		t.Fatal(awake.Alerts[1].Message)
	}
}

func TestUnknownHostReadingsDoNotHold(t *testing.T) {
	eng := NewEngine(nil)
	host := macPlugin()
	now := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	got := eng.DecideMachine(now, sysprobe.Snapshot{}, samples(host))
	if got.Hold || len(got.Alerts) != 0 {
		t.Fatalf("unknown: %+v", got)
	}
	if got := eng.DecideMachine(now, sysprobe.Snapshot{}, nil); got.Hold || len(got.Alerts) != 0 {
		t.Fatalf("no host plug-in: %+v", got)
	}
}

func TestDiskAlertsOnce(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	if got := eng.DecideMachine(start, hostSnap(false, true, 10, "normal"), samples(host)); len(got.Alerts) != 0 {
		t.Fatalf("on the line: %+v", got)
	}
	low := eng.DecideMachine(start, hostSnap(false, true, 9.9, "normal"), samples(host))
	if len(low.Alerts) != 1 || low.Alerts[0].Message != "Free disk space is low: 9.9% is left." {
		t.Fatalf("low: %+v", low)
	}
	if again := eng.DecideMachine(start.Add(time.Minute), hostSnap(false, true, 9, "normal"), samples(host)); len(again.Alerts) != 0 {
		t.Fatalf("repeat: %+v", again)
	}
	eng.DecideMachine(start.Add(2*time.Minute), hostSnap(false, true, 50, "normal"), samples(host))
	next := eng.DecideMachine(start.Add(3*time.Minute), hostSnap(false, true, 9, "normal"), samples(host))
	if len(next.Alerts) != 1 || next.Alerts[0].Kind != KindDiskLow {
		t.Fatalf("new episode: %+v", next)
	}
}

func TestDiskStaysQuietWhileHeld(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	held := eng.DecideMachine(start, hostSnap(false, false, 5, "normal"), samples(host))
	if !held.Hold || len(held.Alerts) != 1 || held.Alerts[0].Kind != KindNetworkDown {
		t.Fatalf("held: %+v", held)
	}
	back := eng.DecideMachine(start.Add(time.Minute), hostSnap(false, true, 5, "normal"), samples(host))
	if back.Hold || len(back.Alerts) != 2 || back.Alerts[1].Kind != KindDiskLow {
		t.Fatalf("after hold: %+v", back.Alerts)
	}
}

func TestCPUHogIgnoresSpikesAndNamesTheCulprit(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	high := func(pid int, name string, pct float64) sysprobe.Snapshot {
		return hostSnap(false, true, 40, "normal", sysprobe.Process{PID: pid, Name: name, CPUKnown: true, CPUPercent: pct})
	}
	if got := eng.DecideMachine(start, high(7, "ExampleTool", 95), samples(host)); len(got.Alerts) != 0 {
		t.Fatalf("first high sample: %+v", got)
	}
	if got := eng.DecideMachine(start.Add(time.Minute), high(7, "ExampleTool", 1), samples(host)); len(got.Alerts) != 0 || eng.StopAllowed("ExampleTool") {
		t.Fatalf("spike reset: %+v", got)
	}
	eng.DecideMachine(start.Add(2*time.Minute), high(7, "ExampleTool", 95), samples(host))
	if got := eng.DecideMachine(start.Add(6*time.Minute), high(7, "ExampleTool", 95), samples(host)); len(got.Alerts) != 0 {
		t.Fatalf("4 minutes into the new window: %+v", got)
	}
	got := eng.DecideMachine(start.Add(7*time.Minute), high(7, "ExampleTool", 90), samples(host))
	if len(got.Alerts) != 1 || got.Alerts[0].Kind != KindCPUHog || got.Alerts[0].ServiceID != UnwatchedID {
		t.Fatalf("unwatched: %+v", got)
	}
	if got.Alerts[0].Message != "A process that is not on the watched list (ExampleTool) has used 90% of the CPU for 5 minutes." {
		t.Fatal(got.Alerts[0].Message)
	}
	if !got.Alerts[0].OfferFix || len(got.Alerts[0].Actions) != 1 || got.Alerts[0].Actions[0] != plugins.FixStop {
		t.Fatalf("actions: %+v", got.Alerts[0])
	}
	if !eng.StopAllowed("ExampleTool") || eng.StopAllowed("other") {
		t.Fatal("stop allowlist")
	}
	if again := eng.DecideMachine(start.Add(8*time.Minute), high(7, "ExampleTool", 90), samples(host)); len(again.Alerts) != 0 {
		t.Fatalf("repeat hog: %+v", again)
	}

	eng = NewEngine(nil)
	eng.DecideMachine(start, high(7, "one", 90), samples(host))
	if got := eng.DecideMachine(start.Add(4*time.Minute), high(8, "two", 90), samples(host)); len(got.Alerts) != 0 {
		t.Fatalf("culprit change: %+v", got)
	}
	got = eng.DecideMachine(start.Add(9*time.Minute), high(8, "two", 91), samples(host))
	if len(got.Alerts) != 1 || !strings.Contains(got.Alerts[0].Message, "(two)") {
		t.Fatalf("new culprit: %+v", got)
	}

	tie := hostSnap(false, true, 40, "normal",
		sysprobe.Process{PID: 5, Name: "later", CPUKnown: true, CPUPercent: 90},
		sysprobe.Process{PID: 3, Name: "earlier", CPUKnown: true, CPUPercent: 90},
	)
	eng = NewEngine(nil)
	eng.DecideMachine(start, tie, samples(host))
	got = eng.DecideMachine(start.Add(5*time.Minute), tie, samples(host))
	if len(got.Alerts) != 1 || got.Alerts[0].Process != "earlier" {
		t.Fatalf("tie: %+v", got)
	}
}

func TestWatchedHogOffersStopOrRestartOnly(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	service := codexPlugin()
	snap := hostSnap(false, true, 40, "normal", sysprobe.Process{PID: 4, Name: "codex", CPUKnown: true, CPUPercent: 90})
	list := samples(host, Sample{Plugin: service, Outcomes: healthyOutcomes()})
	eng.DecideMachine(start, snap, list)
	got := eng.DecideMachine(start.Add(5*time.Minute), snap, list)
	if len(got.Alerts) != 1 {
		t.Fatalf("%+v", got)
	}
	alert := got.Alerts[0]
	if alert.ServiceID != "codex" || alert.Process != "codex" {
		t.Fatalf("%+v", alert)
	}
	if alert.Message != "Codex has used 90% of the CPU for 5 minutes." {
		t.Fatal(alert.Message)
	}
	if !alert.OfferFix || strings.Join(alert.Actions, ",") != "stop,restart" || alert.Action != plugins.FixStop {
		t.Fatalf("actions %+v", alert)
	}
	if eng.StopAllowed("codex") {
		t.Fatal("watched stop is approved on the plug-in, not the unwatched list")
	}

	restartOnly := service
	restartOnly.Fixes = map[string]plugins.Fix{plugins.FixRestart: {Kind: plugins.FixRestart}}
	eng = NewEngine(nil)
	list = samples(host, Sample{Plugin: restartOnly, Outcomes: healthyOutcomes()})
	eng.DecideMachine(start, snap, list)
	got = eng.DecideMachine(start.Add(5*time.Minute), snap, list)
	if strings.Join(got.Alerts[0].Actions, ",") != "restart" {
		t.Fatalf("%+v", got.Alerts[0])
	}

	noFix := service
	noFix.Fixes = nil
	eng = NewEngine(nil)
	list = samples(host, Sample{Plugin: noFix, Outcomes: healthyOutcomes()})
	eng.DecideMachine(start, snap, list)
	got = eng.DecideMachine(start.Add(5*time.Minute), snap, list)
	if got.Alerts[0].OfferFix || got.Alerts[0].ServiceID != "codex" {
		t.Fatalf("%+v", got.Alerts[0])
	}
}

func TestMemoryHogDurationAndLevel(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	procs := []sysprobe.Process{
		{PID: 4, Name: "small", MemoryKnown: true, MemoryBytes: 10},
		{PID: 9, Name: "ExampleTool", MemoryKnown: true, MemoryBytes: 80},
	}
	warn := hostSnap(false, true, 40, "warn", procs...)
	if got := eng.DecideMachine(start, warn, samples(host)); len(got.Alerts) != 0 {
		t.Fatalf("start: %+v", got)
	}
	if got := eng.DecideMachine(start.Add(4*time.Minute), warn, samples(host)); len(got.Alerts) != 0 {
		t.Fatalf("short: %+v", got)
	}
	normal := hostSnap(false, true, 40, "normal", procs...)
	eng.DecideMachine(start.Add(5*time.Minute), normal, samples(host))
	eng.DecideMachine(start.Add(6*time.Minute), warn, samples(host))
	if got := eng.DecideMachine(start.Add(10*time.Minute), warn, samples(host)); len(got.Alerts) != 0 {
		t.Fatalf("window restarted: %+v", got)
	}
	got := eng.DecideMachine(start.Add(11*time.Minute), hostSnap(false, true, 40, "critical", procs...), samples(host))
	if len(got.Alerts) != 1 || got.Alerts[0].Kind != KindMemoryHog || got.Alerts[0].Process != "ExampleTool" {
		t.Fatalf("%+v", got)
	}
	if got.Alerts[0].Message != "A process that is not on the watched list (ExampleTool) is the largest memory user, and memory pressure has stayed at critical for 5 minutes." {
		t.Fatal(got.Alerts[0].Message)
	}

	criticalOnly := host
	criticalOnly.Checks[3].Level = "critical"
	eng = NewEngine(nil)
	eng.DecideMachine(start, warn, samples(criticalOnly))
	if got := eng.DecideMachine(start.Add(5*time.Minute), warn, samples(criticalOnly)); len(got.Alerts) != 0 {
		t.Fatalf("warn is below critical: %+v", got)
	}
}

func TestResourceTimerHoldsWithTheNetwork(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	high := hostSnap(false, true, 40, "normal", sysprobe.Process{PID: 7, Name: "ExampleTool", CPUKnown: true, CPUPercent: 90})
	eng.DecideMachine(start, high, samples(host))
	held := high
	held.Host.NetworkUp = false
	got := eng.DecideMachine(start.Add(time.Minute), held, samples(host))
	if !got.Hold || alertKinds(got) != KindNetworkDown {
		t.Fatalf("hold: %+v", got)
	}
	got = eng.DecideMachine(start.Add(6*time.Minute), high, samples(host))
	if got.Hold || alertKinds(got) != KindNetworkBack+","+KindCPUHog {
		t.Fatalf("fires after hold: %s", alertKinds(got))
	}

	eng = NewEngine(nil)
	low := hostSnap(false, true, 40, "normal", sysprobe.Process{PID: 7, Name: "ExampleTool", CPUKnown: true, CPUPercent: 10})
	eng.DecideMachine(start, low, samples(host))
	held = high
	held.Host.NetworkUp = false
	eng.DecideMachine(start.Add(time.Minute), held, samples(host))
	if got := eng.DecideMachine(start.Add(2*time.Minute), high, samples(host)); alertKinds(got) != KindNetworkBack {
		t.Fatalf("should not start during hold: %s", alertKinds(got))
	}
	got = eng.DecideMachine(start.Add(7*time.Minute), high, samples(host))
	if alertKinds(got) != KindCPUHog {
		t.Fatalf("new window: %s", alertKinds(got))
	}
}

func TestHogDoesNotCountTowardKeepsHappening(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(func() time.Time { return start })
	service := codexPlugin()
	host := macPlugin()
	down := []checks.Outcome{{Type: plugins.CheckProcessRunning, NotRunning: true, Failed: true}}
	eng.Decide(service, down)
	first := eng.Decide(service, down)
	if first.Alerts[0].Kind != KindDown || !first.Alerts[0].OfferFix {
		t.Fatalf("episode 1: %+v", first)
	}
	snap := hostSnap(false, true, 40, "normal", sysprobe.Process{PID: 7, Name: "ExampleTool", CPUKnown: true, CPUPercent: 95})
	eng.DecideMachine(start, snap, samples(host))
	if hog := eng.DecideMachine(start.Add(5*time.Minute), snap, samples(host)); len(hog.Alerts) != 1 {
		t.Fatalf("hog: %+v", hog)
	}
	eng.Decide(service, healthyOutcomes())
	eng.Decide(service, down)
	second := eng.Decide(service, down)
	if len(second.Alerts) != 1 || second.Alerts[0].Kind != KindDown || !second.Alerts[0].OfferFix {
		t.Fatalf("episode 2 should still offer a fix: %+v", second)
	}
}

func TestCustomHostMessage(t *testing.T) {
	host := macPlugin()
	host.Messages.Sleep = "Custom sleep."
	eng := NewEngine(nil)
	got := eng.DecideMachine(time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC), hostSnap(true, true, 40, "normal"), samples(host))
	if len(got.Alerts) != 1 || got.Alerts[0].Message != "Custom sleep." {
		t.Fatalf("%+v", got)
	}
}

func alertKinds(v MachineVerdict) string {
	parts := make([]string, len(v.Alerts))
	for i, alert := range v.Alerts {
		parts[i] = alert.Kind
	}
	return strings.Join(parts, ",")
}
