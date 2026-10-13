package sysprobe

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestProcessLifetimeSamplesBracketMetadataAndDropReusedPID(t *testing.T) {
	generation := uint64(1000)
	var calls []string
	starts := func(context.Context) map[int]uint64 {
		calls = append(calls, "start-times")
		return map[int]uint64{4: generation, 6: 2000}
	}
	metadata := func(context.Context) ([]Process, error) {
		calls = append(calls, "metadata")
		old := Process{PID: 4, Name: "old-app", Exe: "/opt/old-app", Cmd: "old-app --flag"}
		// The PID is reused after command/path metadata was read. Its new
		// start time must not be attached to the old image's metadata.
		generation++
		return []Process{old, {PID: 6, Name: "stable"}}, nil
	}
	procs, err := sampleProcessLifetimes(context.Background(), starts, metadata)
	if err != nil || len(procs) != 1 || procs[0].PID != 6 || procs[0].StartTime != 2000 {
		t.Fatalf("mixed lifetime retained: %+v %v", procs, err)
	}
	if !reflect.DeepEqual(calls, []string{"start-times", "metadata", "start-times"}) {
		t.Fatalf("metadata not bracketed: %v", calls)
	}
}

func TestProcessLifetimeSampleKeepsUnverifiedPIDVisible(t *testing.T) {
	for _, scenario := range []string{"before-unavailable", "after-unavailable", "both-unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			reads := 0
			starts := func(context.Context) map[int]uint64 {
				reads++
				if scenario == "both-unavailable" || scenario == "before-unavailable" && reads == 1 || scenario == "after-unavailable" && reads == 2 {
					return nil
				}
				return map[int]uint64{4: 1000}
			}
			metadata := func(context.Context) ([]Process, error) {
				return []Process{{PID: 4, Name: "app", StartTime: 999}}, nil
			}
			procs, err := sampleProcessLifetimes(context.Background(), starts, metadata)
			if err != nil || len(procs) != 1 || procs[0].PID != 4 || procs[0].Name != "app" || procs[0].StartTime != 0 {
				t.Fatalf("unverified PID hidden or trusted: %+v %v", procs, err)
			}
		})
	}
}

func TestProcessLifetimeSamplingHonorsCancellationAndMetadataErrors(t *testing.T) {
	for _, phase := range []string{"before", "first-starts", "metadata", "last-starts", "metadata-error"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			metadataCalls := 0
			if phase == "before" {
				cancel()
			}
			starts := func(context.Context) map[int]uint64 {
				reads++
				if phase == "first-starts" && reads == 1 || phase == "last-starts" && reads == 2 {
					cancel()
				}
				return map[int]uint64{4: 1000}
			}
			wantErr := errors.New("metadata failed")
			metadata := func(context.Context) ([]Process, error) {
				metadataCalls++
				if phase == "metadata" {
					cancel()
				}
				if phase == "metadata-error" {
					return nil, wantErr
				}
				return []Process{{PID: 4}}, nil
			}
			procs, err := sampleProcessLifetimes(ctx, starts, metadata)
			if phase != "metadata-error" {
				wantErr = context.Canceled
			}
			if !errors.Is(err, wantErr) || len(procs) != 0 {
				t.Fatalf("bad sample after failure: %+v %v", procs, err)
			}
			if phase == "before" && reads != 0 || phase == "first-starts" && metadataCalls != 0 || (phase == "metadata" || phase == "metadata-error") && reads != 1 {
				t.Fatalf("continued sampling after failure: reads=%d metadata=%d", reads, metadataCalls)
			}
		})
	}
}
