package checks

import (
	"testing"

	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

func examplePlugin() plugins.Plugin {
	return plugins.Plugin{
		ID:      "example-desktop-app",
		Name:    "Example Desktop App",
		Process: plugins.ProcessMatch{Match: "example-desktop-app"},
		Checks: []plugins.Check{
			{Type: plugins.CheckProcessRunning},
			{Type: plugins.CheckOutboundTCP, Port: 443, Consecutive: 3},
		},
		Fixes: map[string]plugins.Fix{
			plugins.FixRestart:      {Kind: plugins.FixRestart},
			plugins.FixForceRestart: {Kind: plugins.FixForceRestart},
		},
	}
}

func snap(running bool, ports ...int) sysprobe.Snapshot {
	s := sysprobe.Snapshot{OutboundPorts: map[int][]int{}}
	if running {
		s.Processes = []sysprobe.Process{
			{PID: 4, PPID: 1, Name: "example-desktop-app", Exe: "example-desktop-app"},
			{PID: 5, PPID: 4, Name: "helper", Exe: "helper"},
		}
		if len(ports) > 0 {
			s.OutboundPorts[5] = append([]int(nil), ports...)
		}
	}
	return s
}

func TestOutboundZeroForNChecksIsStuck(t *testing.T) {
	runner := NewRunner(NewRegistry())
	p := examplePlugin()

	first, err := runner.Run(p, snap(true, 443, 443))
	if err != nil {
		t.Fatal(err)
	}
	if !AllHealthy(first) {
		t.Fatalf("healthy sample: %+v", first)
	}

	for i := 1; i <= 2; i++ {
		got, err := runner.Run(p, snap(true))
		if err != nil {
			t.Fatal(err)
		}
		if got[1].Failed || got[1].Stuck || got[1].Healthy {
			t.Fatalf("sample %d should be under the streak: %+v", i, got[1])
		}
	}
	stuck, err := runner.Run(p, snap(true))
	if err != nil {
		t.Fatal(err)
	}
	if !stuck[0].Healthy || stuck[0].NotRunning {
		t.Fatalf("process should still be up: %+v", stuck[0])
	}
	if !stuck[1].Stuck || !stuck[1].Failed || stuck[1].Healthy {
		t.Fatalf("expected stuck, got %+v", stuck[1])
	}

	recovered, err := runner.Run(p, snap(true, 443))
	if err != nil {
		t.Fatal(err)
	}
	if !AllHealthy(recovered) {
		t.Fatalf("connection should reset the streak: %+v", recovered)
	}
	again, err := runner.Run(p, snap(true))
	if err != nil {
		t.Fatal(err)
	}
	if again[1].Stuck {
		t.Fatal("streak should have restarted at 1")
	}
}

func TestProcessDownSkipsHealthSignalAndResetsStreak(t *testing.T) {
	reg := NewRegistry()
	fake := &fakeSignal{}
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	p := examplePlugin()
	p.Checks = append(p.Checks, plugins.Check{Type: "fake_signal", Consecutive: 1})
	runner := NewRunner(reg)

	if _, err := runner.Run(p, snap(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(p, snap(true)); err != nil {
		t.Fatal(err)
	}
	before := fake.hits
	down, err := runner.Run(p, snap(false))
	if err != nil {
		t.Fatal(err)
	}
	if !down[0].NotRunning || !down[0].Failed {
		t.Fatalf("expected not running: %+v", down[0])
	}
	if !down[1].Skipped || !down[2].Skipped {
		t.Fatalf("later checks should be skipped: %+v", down)
	}
	if fake.hits != before {
		t.Fatalf("health signal ran while the process was down: hits %d to %d", before, fake.hits)
	}
	back, err := runner.Run(p, snap(true))
	if err != nil {
		t.Fatal(err)
	}
	if back[1].Stuck {
		t.Fatal("a down sample should reset the outbound streak")
	}
	if fake.hits != before+1 {
		t.Fatalf("fake signal hits = %d, want %d", fake.hits, before+1)
	}
}

func TestPluggableSignal(t *testing.T) {
	reg := NewRegistry()
	fake := &fakeSignal{}
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	costs := reg.Costs()
	for name, cost := range plugins.BuiltinCosts() {
		if costs[name] != cost {
			t.Fatalf("cost of %s = %d, want %d", name, costs[name], cost)
		}
	}
	p := examplePlugin()
	p.Checks = []plugins.Check{
		{Type: plugins.CheckProcessRunning},
		{Type: "fake_signal", Consecutive: 2},
	}
	if err := plugins.Validate(&p, costs); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(reg)
	first, err := runner.Run(p, snap(true))
	if err != nil {
		t.Fatal(err)
	}
	if first[1].Failed {
		t.Fatalf("first fake sample should pass: %+v", first[1])
	}
	second, err := runner.Run(p, snap(true))
	if err != nil {
		t.Fatal(err)
	}
	if !second[1].Stuck || !second[1].Failed {
		t.Fatalf("second fake sample should fail: %+v", second[1])
	}
}

func TestUnknownCheckType(t *testing.T) {
	runner := NewRunner(NewRegistry())
	p := examplePlugin()
	p.Checks = []plugins.Check{{Type: "shell"}}
	if _, err := runner.Run(p, snap(true)); err == nil {
		t.Fatal("expected unknown check type to fail")
	}
}

type fakeSignal struct {
	hits int
}

func (f *fakeSignal) Type() string { return "fake_signal" }
func (f *fakeSignal) Cost() int    { return 15 }
func (f *fakeSignal) Run(in Input) Outcome {
	f.hits++
	if in.Spec.Consecutive > 0 && f.hits >= in.Spec.Consecutive {
		return Outcome{Type: "fake_signal", Failed: true, Stuck: true, Detail: "fake signal failed"}
	}
	return Outcome{Type: "fake_signal", Healthy: true, Detail: "fake signal ok"}
}
