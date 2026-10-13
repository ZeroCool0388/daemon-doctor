package sysprobe

import (
	"context"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinStartTimeKeepsMicrosecondPrecision(t *testing.T) {
	first := darwinStartTime(unix.Timeval{Sec: 100, Usec: 1})
	second := darwinStartTime(unix.Timeval{Sec: 100, Usec: 2})
	if first != 100_000_001 || second != first+1 {
		t.Fatalf("start times rounded: %d %d", first, second)
	}
	for _, invalid := range []unix.Timeval{{}, {Sec: -1}, {Sec: 100, Usec: -1}, {Sec: 100, Usec: 1_000_000}} {
		if got := darwinStartTime(invalid); got != 0 {
			t.Fatalf("invalid time accepted: %+v = %d", invalid, got)
		}
	}
}

func TestAttachStartTimesForCurrentDarwinProcess(t *testing.T) {
	procs := []Process{{PID: os.Getpid()}}
	first := attachStartTimes(context.Background(), procs)[0].StartTime
	if first == 0 {
		t.Skip("kernel process start time is unavailable in this environment")
	}
	second := attachStartTimes(context.Background(), procs)[0].StartTime
	if second != first {
		t.Fatalf("same lifetime changed: %d %d", first, second)
	}
}
