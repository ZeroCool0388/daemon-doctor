package rules

import (
	"slices"
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
	if back.Alerts[0].Message != "Network back at 21:07 UTC. 2 of 3 services healthy.\nOffline:\n• Syncthing\nOnline:\n• Codex\n• This Mac" {
		t.Fatal(back.Alerts[0].Message)
	}
}

func TestNetworkBackServiceLists(t *testing.T) {
	healthy := func(name string) Sample {
		return Sample{Plugin: plugins.Plugin{Name: name}, Outcomes: healthyOutcomes()}
	}
	offline := func(name string) Sample {
		return Sample{Plugin: plugins.Plugin{Name: name}, Outcomes: []checks.Outcome{{Healthy: false}}}
	}
	for _, tt := range []struct {
		name    string
		samples []Sample
		want    string
	}{
		{
			name:    "mixed",
			samples: []Sample{offline("Zulu Service"), healthy("Codex"), offline("Grok Bot"), healthy("ChatGPT")},
			want:    "Network back at 21:07 UTC. 2 of 4 services healthy.\nOffline:\n• Grok Bot\n• Zulu Service\nOnline:\n• ChatGPT\n• Codex",
		},
		{
			name:    "all healthy",
			samples: []Sample{healthy("Codex"), healthy("ChatGPT")},
			want:    "Network back at 21:07 UTC. 2 of 2 services healthy.\nOnline:\n• ChatGPT\n• Codex",
		},
		{
			name:    "all offline",
			samples: []Sample{offline("Zulu Service"), offline("Grok Bot")},
			want:    "Network back at 21:07 UTC. 0 of 2 services healthy.\nOffline:\n• Grok Bot\n• Zulu Service",
		},
		{
			name: "no services",
			want: "Network back at 21:07 UTC. 0 of 0 services healthy.",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reversed := slices.Clone(tt.samples)
			slices.Reverse(reversed)
			for _, samples := range [][]Sample{tt.samples, reversed} {
				got := networkBackAlert(macPlugin(), samples, time.Date(2026, 1, 2, 21, 7, 0, 0, time.UTC))
				if got.Message != tt.want {
					t.Fatalf("message:\n%s\nwant:\n%s", got.Message, tt.want)
				}
			}
		})
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
	if strings.Contains(awake.Alerts[1].Message, "Offline:") {
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
	eng.DecideMachine(start.Add(8*time.Minute), normal, samples(host))
	eng.DecideMachine(start.Add(9*time.Minute), warn, samples(host))
	if got := eng.DecideMachine(start.Add(13*time.Minute), warn, samples(host)); len(got.Alerts) != 0 {
		t.Fatalf("window restarted: %+v", got)
	}
	got := eng.DecideMachine(start.Add(14*time.Minute), hostSnap(false, true, 40, "critical", procs...), samples(host))
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

func TestMemoryPressureTimerIgnoresTopPIDChanges(t *testing.T) {
	for _, watchedAtAlert := range []bool{false, true} {
		t.Run(map[bool]string{false: "unwatched", true: "watched"}[watchedAtAlert], func(t *testing.T) {
			start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
			eng := NewEngine(nil)
			host := macPlugin()
			list := samples(host, Sample{Plugin: codexPlugin(), Outcomes: healthyOutcomes()})
			var alerts []Alert
			for minute := 0; minute <= 6; minute++ {
				codexTop := minute%2 == 0
				if watchedAtAlert {
					codexTop = !codexTop
				}
				codexBytes, toolBytes := int64(80), int64(90)
				if codexTop {
					codexBytes, toolBytes = toolBytes, codexBytes
				}
				snap := hostSnap(false, true, 40, "warn",
					sysprobe.Process{PID: 4, Name: "codex", MemoryKnown: true, MemoryBytes: codexBytes},
					sysprobe.Process{PID: 9, Name: "ExampleTool", MemoryKnown: true, MemoryBytes: toolBytes})
				got := eng.DecideMachine(start.Add(time.Duration(minute)*time.Minute), snap, list)
				if minute < 5 && len(got.Alerts) != 0 {
					t.Fatalf("early alert at minute %d: %+v", minute, got)
				}
				alerts = append(alerts, got.Alerts...)
			}
			if len(alerts) != 1 || alerts[0].Kind != KindMemoryHog || !alerts[0].At.Equal(start.Add(5*time.Minute)) {
				t.Fatalf("expected one alert at five minutes despite alternating PIDs: %+v", alerts)
			}
			wantName, wantID, wantActions := "ExampleTool", UnwatchedID, "stop"
			if watchedAtAlert {
				wantName, wantID, wantActions = "codex", "codex", "stop,restart"
			}
			if alerts[0].Process != wantName || alerts[0].ServiceID != wantID || strings.Join(alerts[0].Actions, ",") != wantActions {
				t.Fatalf("alert did not name the current top process with its approved fixes: %+v", alerts[0])
			}
		})
	}
}

func TestMemoryPressureTimerSurvivesBriefNormalDips(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	proc := sysprobe.Process{PID: 9, Name: "ExampleTool", MemoryKnown: true, MemoryBytes: 80}
	var alerts []Alert
	for minute, pressure := range []string{"warn", "warn", "normal", "warn", "normal", "warn", "warn"} {
		got := eng.DecideMachine(start.Add(time.Duration(minute)*time.Minute), hostSnap(false, true, 40, pressure, proc), samples(host))
		if slices.Contains(got.Normal, KindMemoryHog) {
			t.Fatalf("brief normal dip cleared the pressure incident at minute %d", minute)
		}
		alerts = append(alerts, got.Alerts...)
	}
	if len(alerts) != 1 || alerts[0].Kind != KindMemoryHog || !alerts[0].At.Equal(start.Add(5*time.Minute)) {
		t.Fatalf("expected one memory alert despite one-minute normal dips: %+v", alerts)
	}
}

func TestMemoryPressureRecoveryGraceResetsOnce(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	proc := sysprobe.Process{PID: 9, Name: "ExampleTool", MemoryKnown: true, MemoryBytes: 80}
	observe := func(minute int, pressure string) MachineVerdict {
		return eng.DecideMachine(start.Add(time.Duration(minute)*time.Minute), hostSnap(false, true, 40, pressure, proc), samples(host))
	}
	observe(0, "warn")
	if got := observe(5, "warn"); len(got.Alerts) != 1 {
		t.Fatalf("expected initial memory alert: %+v", got)
	}
	for _, minute := range []int{6, 7, 8} {
		if got := observe(minute, "normal"); slices.Contains(got.Normal, KindMemoryHog) || len(got.Alerts) != 0 {
			t.Fatalf("recovery before three continuous minutes below the level: %+v", got)
		}
	}
	if got := observe(9, "normal"); !slices.Contains(got.Normal, KindMemoryHog) {
		t.Fatalf("missing recovery after three minutes: %+v", got)
	}
	if got := observe(10, "normal"); slices.Contains(got.Normal, KindMemoryHog) {
		t.Fatalf("memory recovery repeated: %+v", got)
	}
	for _, minute := range []int{11, 15} {
		if got := observe(minute, "warn"); len(got.Alerts) != 0 {
			t.Fatalf("memory timer did not reset after recovery: %+v", got)
		}
	}
	if got := observe(16, "warn"); len(got.Alerts) != 1 || got.Alerts[0].Kind != KindMemoryHog {
		t.Fatalf("new pressure incident did not alert: %+v", got)
	}
}

func TestMemoryPressureAlertsWithoutProcess(t *testing.T) {
	start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
	eng := NewEngine(nil)
	host := macPlugin()
	for minute := 0; minute <= 6; minute++ {
		got := eng.DecideMachine(start.Add(time.Duration(minute)*time.Minute), hostSnap(false, true, 40, "warn"), samples(host))
		if minute != 5 {
			if len(got.Alerts) != 0 {
				t.Fatalf("unexpected alert at minute %d: %+v", minute, got)
			}
			continue
		}
		if len(got.Alerts) != 1 {
			t.Fatalf("pressure without a top process never alerted: %+v", got)
		}
		alert := got.Alerts[0]
		if alert.Kind != KindMemoryHog || alert.ServiceID != host.ID || alert.ServiceName != host.Name || alert.Process != "" || alert.OfferFix || len(alert.Actions) != 0 || alert.Action != "" {
			t.Fatalf("machine pressure alert must not offer a process fix: %+v", alert)
		}
		if alert.Message != "Memory pressure has stayed at warning for 5 minutes." {
			t.Fatalf("expected a plain machine pressure message: %q", alert.Message)
		}
	}
	proc := sysprobe.Process{PID: 9, Name: "ExampleTool", MemoryKnown: true, MemoryBytes: 80}
	if got := eng.DecideMachine(start.Add(7*time.Minute), hostSnap(false, true, 40, "warn", proc), samples(host)); len(got.Alerts) != 0 || eng.StopAllowed(proc.Name) {
		t.Fatalf("later process attribution repeated the machine alert or granted an unoffered stop: %+v", got)
	}
}

func TestMemoryPressureFixesStayWithTheAlertedProcess(t *testing.T) {
	for _, watched := range []bool{false, true} {
		t.Run(map[bool]string{false: "unwatched", true: "watched"}[watched], func(t *testing.T) {
			start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
			eng := NewEngine(nil)
			host := macPlugin()
			list := samples(host, Sample{Plugin: codexPlugin(), Outcomes: healthyOutcomes()})
			proc := sysprobe.Process{PID: 9, Name: "ExampleTool", MemoryKnown: true, MemoryBytes: 80}
			if watched {
				proc.Name = "codex"
			}
			observe := func(minute int, pressure string, procs ...sysprobe.Process) MachineVerdict {
				return eng.DecideMachine(start.Add(time.Duration(minute)*time.Minute), hostSnap(false, true, 40, pressure, procs...), list)
			}
			observe(0, "warn", proc)
			got := observe(5, "warn", proc)
			if len(got.Alerts) != 1 {
				t.Fatalf("expected a memory alert: %+v", got)
			}
			alert := got.Alerts[0]
			if !eng.AlertActive(alert) || !eng.FixEligible(alert) || eng.StopAllowed(proc.Name) == watched {
				t.Fatal("named process did not receive the expected fix permissions")
			}
			// A brief dip keeps the incident, but a process fix is no longer needed.
			got = observe(6, "normal", proc)
			if slices.Contains(got.Normal, KindMemoryHog) || !eng.AlertActive(alert) || eng.FixEligible(alert) || eng.StopAllowed(proc.Name) {
				t.Fatalf("brief dip cleared the incident or retained a stale fix: %+v", got)
			}
			got = observe(7, "warn", proc)
			if len(got.Alerts) != 0 || !eng.AlertActive(alert) || !eng.FixEligible(alert) {
				t.Fatalf("returning pressure repeated the alert or lost its current target: %+v", got)
			}
			other := sysprobe.Process{PID: 10, Name: "OtherTool", MemoryKnown: true, MemoryBytes: 90}
			got = observe(8, "warn", proc, other)
			if len(got.Alerts) != 0 || !eng.AlertActive(alert) || eng.FixEligible(alert) || eng.StopAllowed(proc.Name) || eng.StopAllowed(other.Name) {
				t.Fatalf("changing the top process repeated the alert or granted a stale/unoffered fix: %+v", got)
			}
			got = observe(9, "warn")
			if len(got.Alerts) != 0 || !eng.AlertActive(alert) || eng.FixEligible(alert) || eng.StopAllowed(proc.Name) {
				t.Fatalf("missing process retained a process permission: %+v", got)
			}
			proc.PID++ // A replacement with the same name is not the alerted process.
			got = observe(10, "warn", proc)
			if len(got.Alerts) != 0 || !eng.AlertActive(alert) || eng.FixEligible(alert) || eng.StopAllowed(proc.Name) {
				t.Fatalf("replacement process inherited the previous alert's permission: %+v", got)
			}
			proc.PID--
			got = observe(11, "warn", proc)
			if len(got.Alerts) != 0 || !eng.AlertActive(alert) || !eng.FixEligible(alert) || eng.StopAllowed(proc.Name) == watched {
				t.Fatalf("original process did not regain its offer without repeating the alert: %+v", got)
			}
			observe(12, "normal", proc)
			observe(15, "normal", proc)
			if eng.AlertActive(alert) || eng.FixEligible(alert) || eng.StopAllowed(proc.Name) {
				t.Fatal("memory recovery retained the incident or its fix permissions")
			}
		})
	}
}

func TestMemoryPressureRecoveryNeedsContinuousKnownReadings(t *testing.T) {
	for _, interruption := range []string{"unknown", "invalid level", "held"} {
		t.Run(interruption, func(t *testing.T) {
			start := time.Date(2026, 1, 2, 21, 0, 0, 0, time.UTC)
			eng := NewEngine(nil)
			host := macPlugin()
			proc := sysprobe.Process{PID: 9, Name: "ExampleTool", MemoryKnown: true, MemoryBytes: 80}
			snap := hostSnap(false, true, 40, "warn", proc)
			eng.DecideMachine(start, snap, samples(host))
			eng.DecideMachine(start.Add(5*time.Minute), snap, samples(host))
			snap.Host.MemoryPressure = "normal"
			eng.DecideMachine(start.Add(6*time.Minute), snap, samples(host))
			paused := snap
			switch interruption {
			case "unknown":
				paused.Host.MemoryPressureKnown = false
			case "invalid level":
				paused.Host.MemoryPressure = "unknown"
			case "held":
				paused.Host.NetworkUp = false
			}
			if got := eng.DecideMachine(start.Add(8*time.Minute), paused, samples(host)); slices.Contains(got.Normal, KindMemoryHog) {
				t.Fatalf("interrupted recovery sent a premature all-clear: %+v", got)
			}
			for _, minute := range []int{9, 11} {
				if got := eng.DecideMachine(start.Add(time.Duration(minute)*time.Minute), snap, samples(host)); slices.Contains(got.Normal, KindMemoryHog) {
					t.Fatalf("interruption counted toward three continuous minutes: %+v", got)
				}
			}
			if got := eng.DecideMachine(start.Add(12*time.Minute), snap, samples(host)); !slices.Contains(got.Normal, KindMemoryHog) {
				t.Fatalf("missing all-clear after confirmed recovery: %+v", got)
			}
		})
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
