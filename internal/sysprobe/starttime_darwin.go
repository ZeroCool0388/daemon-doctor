package sysprobe

import (
	"context"

	"golang.org/x/sys/unix"
)

// Use the kernel's microsecond start time, rather than ps's lstart column,
// which rounds to seconds and can miss two lifetimes within one second. Read
// the process table before and after both ps calls to bracket all metadata.
func darwinStartTimes(ctx context.Context) map[int]uint64 {
	if ctx.Err() != nil {
		return nil
	}
	infos, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	starts := make(map[int]uint64, len(infos))
	for _, info := range infos {
		if ctx.Err() != nil {
			return nil
		}
		if info.Proc.P_pid > 0 {
			starts[int(info.Proc.P_pid)] = darwinStartTime(info.Proc.P_starttime)
		}
	}
	return starts
}

func darwinStartTime(start unix.Timeval) uint64 {
	if start.Sec <= 0 || start.Usec < 0 || start.Usec >= 1_000_000 {
		return 0
	}
	return uint64(start.Sec)*1_000_000 + uint64(start.Usec)
}
