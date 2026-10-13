package fixes

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// OSController signals and launches processes on the local machine.
type OSController struct{}

// The app name is data in argv, never interpolated into AppleScript source.
const quitAppScript = `on run argv
    set appName to item 1 of argv
    if application appName is running then
        tell application appName to quit
    end if
end run`

// Quit asks a macOS app to quit without launching it if it has already exited.
// The caller supplies a deadline for an unresponsive app or automation prompt.
func (OSController) Quit(ctx context.Context, app string) error {
	cmd := quitCommand(ctx, app)
	return cmd.Run()
}

func quitCommand(ctx context.Context, app string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", quitAppScript, app)
	cmd.WaitDelay = 100 * time.Millisecond
	return cmd
}

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

// Launch starts path directly with args. It does not use a shell.
func (OSController) Launch(ctx context.Context, path string, args []string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}
