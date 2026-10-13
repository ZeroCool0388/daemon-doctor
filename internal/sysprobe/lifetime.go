package sysprobe

import "context"

// Bracket all metadata reads, including executable-path lookup, with kernel
// lifetime samples. A changed start time means the PID was reused while the
// metadata was being read, so it must not be paired with either lifetime.
func sampleProcessLifetimes(ctx context.Context, readStarts func(context.Context) map[int]uint64, readMetadata func(context.Context) ([]Process, error)) ([]Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before := readStarts(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	procs, err := readMetadata(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	after := readStarts(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stable := make([]Process, 0, len(procs))
	for _, proc := range procs {
		first, last := before[proc.PID], after[proc.PID]
		if first != 0 && last != 0 && first != last {
			continue
		}
		proc.StartTime = 0
		if first != 0 && first == last {
			proc.StartTime = first
		}
		// Unverifiable metadata remains visible, with no lifetime that can
		// authorize KILL. Absence of a start-time reading is not process exit.
		stable = append(stable, proc)
	}
	return stable, nil
}
