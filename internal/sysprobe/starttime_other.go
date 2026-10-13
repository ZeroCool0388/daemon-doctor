//go:build !darwin

package sysprobe

import "context"

// Linux reads start times with the other process fields in ReadProc.
// takeDarwin is not used on other platforms.
func darwinStartTimes(_ context.Context) map[int]uint64 { return nil }
