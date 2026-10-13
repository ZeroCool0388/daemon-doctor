package fixes

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

// AppQuitter is optional: only the relaunch action needs macOS app control.
// Implementations must stop waiting when ctx ends.
type AppQuitter interface {
	Quit(ctx context.Context, app string) error
}

const relaunchPoll = 100 * time.Millisecond
const relaunchKillWait = 2 * time.Second
const relaunchCheckWait = 5 * time.Second

func (r *Runner) applyRelaunch(ctx context.Context, p plugins.Plugin, fix plugins.Fix, dryRun bool, start time.Time) (Result, error) {
	res := Result{Action: plugins.FixRelaunch, DryRun: dryRun, LaunchArgs: append([]string(nil), fix.Args...)}
	snap, err := r.take(ctx)
	if err != nil {
		return res, err
	}
	// Reuse the built-in checks for the precondition and startup wait. These
	// observations do not advance the monitor's other check streaks or rules.
	launchChecks := p
	launchChecks.Checks = nil
	for _, check := range p.Checks {
		if check.Type == plugins.CheckProcessRunning || check.Type == plugins.CheckLaunchedWithFlags {
			launchChecks.Checks = append(launchChecks.Checks, check)
		}
	}
	checker := checks.NewRunner(checks.NewRegistry())
	outcomes, err := checker.Run(launchChecks, snap)
	if err != nil {
		return res, err
	}
	missing := false
	for _, outcome := range outcomes {
		missing = missing || outcome.MissingFlags
	}
	if !missing {
		return res, fmt.Errorf("relaunch requires a running app missing its required launch settings")
	}
	res.PIDs = sysprobe.SignalOrder(snap, sysprobe.RootPIDsSpec(snap, p.Process.Spec()))
	for _, pid := range res.PIDs {
		if refused(pid) {
			return res, fmt.Errorf("refusing to quit app containing protected pid %d", pid)
		}
	}
	res.Detail = fmt.Sprintf("quit %s, wait for exit, then launch %s", fix.App, formatLaunch(fix.Launcher, fix.Args))
	if dryRun {
		res.WouldLaunch = fix.Launcher
		res.Detail = "dry-run: would " + res.Detail
		return r.finishRelaunch(ctx, p, res, start, nil)
	}
	quitter, ok := r.Control.(AppQuitter)
	if !ok {
		return res, fmt.Errorf("no app quit controller is configured")
	}
	original := processIdentities(snap, res.PIDs)
	quitTimeout, _ := time.ParseDuration(fix.QuitTimeout) // validated by Apply
	quitCtx, cancel := context.WithTimeout(ctx, quitTimeout)
	if err := quitCtx.Err(); err == nil {
		if err = quitter.Quit(quitCtx, fix.App); err != nil {
			res.QuitError = err.Error()
		}
	}
	last, stopped, waitErr := r.waitStopped(quitCtx, p, original)
	cancel()
	if err = ctx.Err(); err != nil {
		return r.finishRelaunch(ctx, p, res, start, err)
	}
	if waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) {
		return r.finishRelaunch(ctx, p, res, start, waitErr)
	}
	if !stopped {
		// Refresh after the grace deadline. Never kill a replacement process
		// just because it has reused a PID or the configured app has reopened.
		last, err = r.take(ctx)
		if err != nil {
			return r.finishRelaunch(ctx, p, res, start, err)
		}
		roots := sysprobe.RootPIDsSpec(last, p.Process.Spec())
		alive := survivingOriginal(last, original)
		for _, pid := range roots {
			if _, ok := alive[pid]; !ok {
				return r.finishRelaunch(ctx, p, res, start, fmt.Errorf("app processes changed during quit; relaunch stopped"))
			}
		}
		// Include surviving orphaned children from the original tree.
		for pid := range alive {
			roots = append(roots, pid)
		}
		killPIDs := sysprobe.SignalOrder(last, roots)
		for _, pid := range killPIDs {
			if refused(pid) {
				return r.finishRelaunch(ctx, p, res, start, fmt.Errorf("refusing to signal pid %d", pid))
			}
		}
		res.Signal = "KILL"
		res.Detail += fmt.Sprintf("; quit timeout, KILL to pids %v", killPIDs)
		if err = r.signal(ctx, &res, killPIDs, syscall.SIGKILL, "", nil, false); err != nil {
			return r.finishRelaunch(ctx, p, res, start, err)
		}
		if res.SignalError != "" {
			return r.finishRelaunch(ctx, p, res, start, fmt.Errorf("kill failed: %s", res.SignalError))
		}
		// Track children discovered since the first sample as well.
		for pid, proc := range processIdentities(last, killPIDs) {
			original[pid] = proc
		}
		killCtx, killCancel := context.WithTimeout(ctx, relaunchKillWait)
		_, stopped, err = r.waitStopped(killCtx, p, original)
		killCancel()
		if err != nil || !stopped {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if errors.Is(err, context.DeadlineExceeded) || err == nil {
				err = fmt.Errorf("app did not exit after KILL; launcher was not run")
			}
			return r.finishRelaunch(ctx, p, res, start, err)
		}
	}
	if err = r.signal(ctx, &res, nil, 0, fix.Launcher, fix.Args, false); err != nil {
		return r.finishRelaunch(ctx, p, res, start, err)
	}
	if res.LaunchError != "" {
		return r.finishRelaunch(ctx, p, res, start, fmt.Errorf("launcher failed: %s", res.LaunchError))
	}
	// A launcher script may return before the app has appeared in a sample.
	checkCtx, checkCancel := context.WithTimeout(ctx, relaunchCheckWait)
	err = r.waitLaunchChecks(checkCtx, launchChecks, checker)
	checkCancel()
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		res.Detail += "; launch settings did not recover within 5s"
		err = nil // the normal full recheck reports the remaining failure
	}
	return r.finishRelaunch(ctx, p, res, start, err)
}

func (r *Runner) take(ctx context.Context) (sysprobe.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return sysprobe.Snapshot{}, err
	}
	snap, err := r.Source.Take(ctx)
	if ctx.Err() != nil {
		return sysprobe.Snapshot{}, ctx.Err()
	}
	return snap, err
}

func (r *Runner) waitStopped(ctx context.Context, p plugins.Plugin, original map[int]sysprobe.Process) (sysprobe.Snapshot, bool, error) {
	var last sysprobe.Snapshot
	for {
		snap, err := r.take(ctx)
		if err != nil {
			return last, false, err
		}
		last = snap
		// Remember new descendants while the original app is still quitting,
		// so a helper orphaned by its parent is included in the exit check.
		var roots []int
		for pid := range survivingOriginal(snap, original) {
			roots = append(roots, pid)
		}
		for pid, proc := range processIdentities(snap, sysprobe.SignalOrder(snap, roots)) {
			original[pid] = proc
		}
		if len(sysprobe.RootPIDsSpec(snap, p.Process.Spec())) == 0 && len(survivingOriginal(snap, original)) == 0 {
			return last, true, nil
		}
		if err := waitRelaunch(ctx); err != nil {
			return last, false, err
		}
	}
}

func (r *Runner) waitLaunchChecks(ctx context.Context, p plugins.Plugin, checker *checks.Runner) error {
	for {
		snap, err := r.take(ctx)
		if err != nil {
			return err
		}
		outcomes, err := checker.Run(p, snap)
		if err != nil || checks.AllHealthy(outcomes) {
			return err
		}
		if err := waitRelaunch(ctx); err != nil {
			return err
		}
	}
}

func waitRelaunch(ctx context.Context) error {
	timer := time.NewTimer(relaunchPoll)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func processIdentities(snap sysprobe.Snapshot, pids []int) map[int]sysprobe.Process {
	wanted := make(map[int]bool, len(pids))
	for _, pid := range pids {
		wanted[pid] = true
	}
	out := map[int]sysprobe.Process{}
	for _, proc := range snap.Processes {
		if wanted[proc.PID] {
			out[proc.PID] = proc
		}
	}
	return out
}

func survivingOriginal(snap sysprobe.Snapshot, original map[int]sysprobe.Process) map[int]sysprobe.Process {
	out := map[int]sysprobe.Process{}
	for _, proc := range snap.Processes {
		old, ok := original[proc.PID]
		if ok && proc.Name == old.Name && proc.Exe == old.Exe && proc.Cmd == old.Cmd {
			out[proc.PID] = proc
		}
	}
	return out
}

func (r *Runner) finishRelaunch(ctx context.Context, p plugins.Plugin, res Result, start time.Time, applyErr error) (Result, error) {
	if res.QuitError != "" {
		res.Detail += "; quit error: " + res.QuitError
	}
	if applyErr != nil {
		res.Detail += "; " + applyErr.Error()
	}
	if ctx.Err() == nil {
		var checkErr error
		res, checkErr = r.finish(ctx, p, res, start)
		if applyErr == nil {
			applyErr = checkErr
		}
	}
	if ctx.Err() != nil {
		applyErr = ctx.Err()
	}
	if applyErr != nil {
		res.Fixed = false
	}
	res.Duration = time.Since(start)
	res.Message = plainMessage(p.Name, res)
	return res, applyErr
}
