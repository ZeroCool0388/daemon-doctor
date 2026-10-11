package checks

import (
	"testing"

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

func TestHostChecksUnknownStayHealthy(t *testing.T) {
	runner := NewRunner(NewRegistry())
	got, err := runner.Run(macPlugin(), sysprobe.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("len %d", len(got))
	}
	for _, outcome := range got {
		if !outcome.Healthy || outcome.Failed || outcome.NotRunning || outcome.Stuck {
			t.Fatalf("unknown reading: %+v", outcome)
		}
	}
}

func TestHostChecksReportBadReadingsWithoutStopping(t *testing.T) {
	runner := NewRunner(NewRegistry())
	snap := sysprobe.Snapshot{
		Host: sysprobe.Host{
			SleepKnown:          true,
			Asleep:              true,
			NetworkKnown:        true,
			NetworkUp:           false,
			DiskKnown:           true,
			DiskFreePercent:     10,
			MemoryPressureKnown: true,
			MemoryPressure:      "warn",
		},
		Processes: []sysprobe.Process{
			{PID: 3, Name: "earlier", CPUKnown: true, CPUPercent: 85},
			{PID: 9, Name: "later", CPUKnown: true, CPUPercent: 84.9},
		},
	}
	got, err := runner.Run(macPlugin(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Healthy || got[0].Failed || got[0].Detail != "the Mac is asleep" {
		t.Fatalf("sleep: %+v", got[0])
	}
	if got[1].Healthy || got[1].Failed {
		t.Fatalf("network: %+v", got[1])
	}
	if !got[2].Healthy {
		t.Fatalf("disk at the line should pass: %+v", got[2])
	}
	if got[3].Healthy || got[3].Failed {
		t.Fatalf("memory: %+v", got[3])
	}
	if got[4].Healthy || got[4].Failed || got[4].Detail != "cpu 85% on earlier" {
		t.Fatalf("cpu: %+v", got[4])
	}

	snap.Host.DiskFreePercent = 9.9
	snap.Host.MemoryPressure = "normal"
	snap.Processes[0].CPUPercent = 84.9
	got, err = runner.Run(macPlugin(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if got[2].Healthy {
		t.Fatalf("disk below the line: %+v", got[2])
	}
	if !got[3].Healthy || !got[4].Healthy {
		t.Fatalf("normal memory and under-line cpu: %+v %+v", got[3], got[4])
	}
}
