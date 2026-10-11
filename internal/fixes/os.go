package fixes

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// OSController signals and launches processes on the local machine.
type OSController struct{}

// Signal sends sig to pid. PID 1, this process, and its parent are refused.
// A process that has already exited is not an error.
func (OSController) Signal(pid int, sig syscall.Signal) error {
	if pid <= 1 || pid == os.Getpid() || pid == os.Getppid() {
		return fmt.Errorf("refusing to signal pid %d", pid)
	}
	err := syscall.Kill(pid, sig)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}

// Launch starts path directly. It does not use a shell and it passes no arguments.
func (OSController) Launch(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}
