// Package fixes runs stop, restart, and force-restart, and only those.
// The action has to be on the plug-in's allowlist, except an unwatched
// stop which the caller has already authorized. Dry-run does not signal
// or launch anything, and every attempt is rechecked. stop never launches.
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
	launch := fix.Launcher
	if action == plugins.FixStop {
		launch = ""
	}
	res := Result{
		Action: action,
		DryRun: dryRun,
		PIDs:   pids,
		Signal: sigName,
	}
	if err := r.signal(ctx, &res, pids, sig, launch, dryRun); err != nil {
		return Result{}, err
	}

	recheck, err := r.Source.Take(ctx)
	if err != nil {
		res.Duration = time.Since(start)
		res.Detail = detail(res, launch)
		res.Message = plainMessage(p.Name, res)
		return res, err
	}
	outcomes, err := r.Checks.Run(p, recheck)
	if err != nil {
		res.Duration = time.Since(start)
		res.Detail = detail(res, launch)
		res.Message = plainMessage(p.Name, res)
		return res, err
	}
	res.Outcomes = outcomes
	res.Fixed = checks.AllHealthy(outcomes)
	res.Duration = time.Since(start)
	res.Detail = detail(res, launch)
	res.Message = plainMessage(p.Name, res)
	return res, nil
}

// ApplyStop signals an unwatched process by its exact name. It never launches.
// The caller decides whether this name was named by a hog rule.
func (r *Runner) ApplyStop(ctx context.Context, processName string, dryRun bool) (Result, error) {
	start := time.Now()
	processName = strings.TrimSpace(processName)
	if err := ValidProcessName(processName); err != nil {
		return Result{}, err
	}
	snap, err := r.Source.Take(ctx)
	if err != nil {
		return Result{}, err
	}
	pids := sysprobe.SignalOrder(snap, sysprobe.RootPIDs(snap, processName))
	res := Result{
		Action: plugins.FixStop,
		DryRun: dryRun,
		PIDs:   pids,
		Signal: "TERM",
	}
	if err := r.signal(ctx, &res, pids, syscall.SIGTERM, "", dryRun); err != nil {
		return Result{}, err
	}
	recheck, err := r.Source.Take(ctx)
	if err != nil {
		res.Duration = time.Since(start)
		res.Detail = detail(res, "")
		res.Message = plainMessage(processName, res)
		return res, err
	}
	res.Fixed = len(sysprobe.RootPIDs(recheck, processName)) == 0
	res.Duration = time.Since(start)
	res.Detail = detail(res, "")
	res.Message = plainMessage(processName, res)
	return res, nil
}

// ValidProcessName rejects an empty name and shell metacharacters.
func ValidProcessName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("process name is required")
	}
	if strings.ContainsAny(name, ";|&`$\\\n\r\x00") {
		return fmt.Errorf("process name contains a character that is not allowed")
	}
	return nil
}

func (r *Runner) signal(ctx context.Context, res *Result, pids []int, sig syscall.Signal, launch string, dryRun bool) error {
	if dryRun {
		res.WouldLaunch = launch
		return nil
	}
	if r.Control == nil {
		return fmt.Errorf("no fix controller is configured")
	}
	for _, pid := range pids {
		if refused(pid) {
			res.SignalError = fmt.Sprintf("refusing to signal pid %d", pid)
			continue
		}
		if err := r.Control.Signal(pid, sig); err != nil {
			res.SignalError = err.Error()
		}
	}
	if launch != "" {
		if err := r.Control.Launch(ctx, launch); err != nil {
			res.LaunchError = err.Error()
		} else {
			res.Launched = launch
		}
	}
	return nil
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
