package sysprobe

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

// liveSource reads the machine this process is running on.
type liveSource struct{}

// Live returns a Source backed by the local operating system.
func Live() Source { return liveSource{} }

func (liveSource) Take(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	switch runtime.GOOS {
	case "linux":
		return ReadProc("/proc")
	case "darwin":
		return takeDarwin(ctx)
	default:
		return Snapshot{}, fmt.Errorf("unsupported operating system %s", runtime.GOOS)
	}
}

func takeDarwin(ctx context.Context) (Snapshot, error) {
	psOut, err := exec.CommandContext(ctx, "ps", "-ax", "-o", "pid=", "-o", "ppid=", "-o", "command=").Output()
	if err != nil {
		return Snapshot{}, fmt.Errorf("ps: %w", err)
	}
	procs, err := ParsePS(string(psOut))
	if err != nil {
		return Snapshot{}, err
	}
	lsofCmd := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pn")
	lsofOut, err := lsofCmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			lsofOut = nil
		} else {
			return Snapshot{}, fmt.Errorf("lsof: %w", err)
		}
	}
	return Snapshot{Processes: procs, OutboundPorts: ParseLsofF(string(lsofOut))}, nil
}
