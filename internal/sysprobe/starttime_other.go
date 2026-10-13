//go:build !darwin

package sysprobe

import "context"

// Linux reads start times with the other process fields in ReadProc.
// takeDarwin is not used on other platforms.
func attachStartTimes(_ context.Context, procs []Process) []Process { return procs }
