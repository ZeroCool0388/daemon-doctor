package sysprobe

import (
	"context"

	"golang.org/x/sys/unix"
)

// Use the kernel's microsecond start time, rather than ps's lstart column,
// which rounds to seconds and can miss two lifetimes within one second.
func attachStartTimes(ctx context.Context, procs []Process) []Process {
	for i := range procs {
		if ctx.Err() != nil {
			break
		}
		info, err := unix.SysctlKinfoProc("kern.proc.pid", procs[i].PID)
		if err == nil {
			procs[i].StartTime = darwinStartTime(info.Proc.P_starttime)
		}
	}
	return procs
}

func darwinStartTime(start unix.Timeval) uint64 {
	if start.Sec <= 0 || start.Usec < 0 || start.Usec >= 1_000_000 {
		return 0
	}
	return uint64(start.Sec)*1_000_000 + uint64(start.Usec)
}
