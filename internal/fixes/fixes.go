// Package fixes runs restart and force-restart, and only those.
// The action has to be on the plug-in's allowlist. Dry-run does not
// signal or launch anything, and every attempt is rechecked.
package fixes

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

// Controller performs the system calls a fix needs.
type Controller interface {
	Signal(pid int, sig syscall.Signal) error
	Launch(ctx context.Context, path string) error
}

// Result is what a fix attempt did, including the recheck.
type Result struct {
	Action      string
	DryRun      bool
	PIDs        []int
	Signal      string
	WouldLaunch string
	Launched    string
	SignalError string
	LaunchError string
	Outcomes    []checks.Outcome
	Fixed       bool
	Message     string
	Detail      string
	Duration    time.Duration
}

// Runner applies allowlisted fixes and rechecks.
type Runner struct {
	Source  sysprobe.Source
	Control Controller
	Checks  *checks.Runner
}

// Apply runs action for p. Unknown or unapproved actions return an error
// and do not signal or launch. Dry-run rechecks without changing anything.
func (r *Runner) Apply(ctx context.Context, p plugins.Plugin, action string, dryRun bool) (Result, error) {
	start := time.Now()
	action = strings.TrimSpace(action)
	if _, ok := plugins.FixAllowlist[action]; !ok {
		return Result{}, fmt.Errorf("unknown fix %q", action)
	}
	if !plugins.Approved(p, action) {
		return Result{}, fmt.Errorf("fix %q is not approved for %s", action, p.ID)
	}
	fix := p.Fixes[action]
	if fix.Launcher != "" {
		if !strings.HasPrefix(fix.Launcher, "/") {
			return Result{}, fmt.Errorf("launcher must be an absolute path")
		}
	}

	snap, err := r.Source.Take(ctx)
	if err != nil {
		return Result{}, err
	}
	pids := sysprobe.SignalOrder(snap, sysprobe.RootPIDs(snap, p.Process.Match))
	sig := syscall.SIGTERM
	sigName := "TERM"
	if action == plugins.FixForceRestart {
		sig = syscall.SIGKILL
		sigName = "KILL"
	}
	res := Result{
		Action: action,
		DryRun: dryRun,
		PIDs:   pids,
		Signal: sigName,
	}
	if dryRun {
		res.WouldLaunch = fix.Launcher
	} else if r.Control == nil {
		return Result{}, fmt.Errorf("no fix controller is configured")
	} else {
		for _, pid := range pids {
			if refused(pid) {
				res.SignalError = fmt.Sprintf("refusing to signal pid %d", pid)
				continue
			}
			if err := r.Control.Signal(pid, sig); err != nil {
				res.SignalError = err.Error()
			}
		}
		if fix.Launcher != "" {
			if err := r.Control.Launch(ctx, fix.Launcher); err != nil {
				res.LaunchError = err.Error()
			} else {
				res.Launched = fix.Launcher
			}
		}
	}

	recheck, err := r.Source.Take(ctx)
	if err != nil {
		res.Duration = time.Since(start)
		res.Detail = detail(res, fix.Launcher)
		res.Message = plainMessage(p.Name, res)
		return res, err
	}
	outcomes, err := r.Checks.Run(p, recheck)
	if err != nil {
		res.Duration = time.Since(start)
		res.Detail = detail(res, fix.Launcher)
		res.Message = plainMessage(p.Name, res)
		return res, err
	}
	res.Outcomes = outcomes
	res.Fixed = checks.AllHealthy(outcomes)
	res.Duration = time.Since(start)
	res.Detail = detail(res, fix.Launcher)
	res.Message = plainMessage(p.Name, res)
	return res, nil
}

func refused(pid int) bool {
	return pid <= 1 || pid == os.Getpid() || pid == os.Getppid()
}

func detail(res Result, launcher string) string {
	var b strings.Builder
	if res.DryRun {
		fmt.Fprintf(&b, "dry-run: would send %s to pids %v", res.Signal, res.PIDs)
		if launcher != "" {
			fmt.Fprintf(&b, " and launch %s", launcher)
		}
	} else {
		fmt.Fprintf(&b, "sent %s to pids %v", res.Signal, res.PIDs)
		if res.Launched != "" {
			fmt.Fprintf(&b, " and launched %s", res.Launched)
		}
	}
	if res.SignalError != "" {
		fmt.Fprintf(&b, "; signal error: %s", res.SignalError)
	}
	if res.LaunchError != "" {
		fmt.Fprintf(&b, "; launch error: %s", res.LaunchError)
	}
	if d := checks.Detail(res.Outcomes); d != "" {
		fmt.Fprintf(&b, "; recheck: %s", d)
	}
	return b.String()
}

func plainMessage(name string, res Result) string {
	if res.DryRun {
		if res.Fixed {
			return "Dry run. No fix was applied. " + name + " looks healthy on recheck."
		}
		return "Dry run. No fix was applied. " + name + " is still not healthy."
	}
	if res.Fixed {
		return "Fixed. " + name + " looks healthy on recheck."
	}
	return "Didn't work. " + name + " is still not healthy."
}
