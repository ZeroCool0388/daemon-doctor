// Package demo replays scripted incidents against the real check rules.
// The services, processes, and clock are fake. Nothing is signalled on
// this machine, and the relay and phone are not used.
package demo

import (
	"context"
	"fmt"
	"io"
	"syscall"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/doctor"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

const (
	pidApp    = 4100
	pidSync   = 4200
	pidMail   = 4300
	pidBridge = 4400
	pidHog    = 4500
)

// Run prints the scripted replay. It returns an error if a scripted fix
// cannot be applied.
func Run(w io.Writer) error {
	clock := &clock{t: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)}
	world := &world{appUp: true, appOut: true, syncUp: true, mailUp: true, bridgeUp: true, networkUp: true}
	src := &sysprobe.MemSource{}
	ctrl := &stage{src: src, world: world}
	doc, err := doctor.New(scriptPlugins(), src, ctrl, nil, nil, clock.now)
	if err != nil {
		return err
	}
	s := &script{w: w, clock: clock, world: world, src: src, doc: doc}
	return s.play()
}

type clock struct {
	t time.Time
}

func (c *clock) now() time.Time { return c.t }

func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

type world struct {
	appUp     bool
	appOut    bool
	syncUp    bool
	mailUp    bool
	bridgeUp  bool
	networkUp bool
	hog       bool
}

func (w *world) snapshot() sysprobe.Snapshot {
	s := sysprobe.Snapshot{
		OutboundPorts: map[int][]int{},
		Host: sysprobe.Host{
			SleepKnown:          true,
			NetworkKnown:        true,
			NetworkUp:           w.networkUp,
			DiskKnown:           true,
			DiskFreePercent:     40,
			MemoryPressureKnown: true,
			MemoryPressure:      "normal",
		},
	}
	add := func(up bool, pid int, name string) {
		if !up {
			return
		}
		s.Processes = append(s.Processes, sysprobe.Process{PID: pid, PPID: 1, Name: name, Exe: name})
	}
	add(w.appUp, pidApp, "example-desktop-app")
	add(w.syncUp, pidSync, "example-sync")
	add(w.mailUp, pidMail, "example-mail")
	add(w.bridgeUp, pidBridge, "example-bridge")
	if w.appUp && w.appOut {
		s.OutboundPorts[pidApp] = []int{443}
	}
	if w.hog {
		s.Processes = append(s.Processes, sysprobe.Process{
			PID: pidHog, PPID: 1, Name: "ExampleTool", Exe: "ExampleTool",
			CPUKnown: true, CPUPercent: 90,
		})
	}
	return s
}

type stage struct {
	src   *sysprobe.MemSource
	world *world
}

func (s *stage) Signal(pid int, sig syscall.Signal) error {
	switch pid {
	case pidApp:
		if sig == syscall.SIGKILL || sig == syscall.SIGTERM {
			s.world.appUp = true
			s.world.appOut = true
		}
	case pidHog:
		s.world.hog = false
	}
	s.src.Set(s.world.snapshot())
	return nil
}

func (s *stage) Launch(context.Context, string) error {
	return fmt.Errorf("demo does not launch programs")
}

type script struct {
	w     io.Writer
	clock *clock
	world *world
	src   *sysprobe.MemSource
	doc   *doctor.Doctor
}

func (s *script) play() error {
	fmt.Fprintln(s.w, "Daemon Doctor demo")
	fmt.Fprintln(s.w, "Fake services. No Mac, no relay, and no phone.")

	fmt.Fprintln(s.w, "")
	fmt.Fprintln(s.w, "Scene 1. Example Desktop App is stuck, then force-restarted.")
	if err := s.step(time.Minute); err != nil {
		return err
	}
	s.world.appOut = false
	if err := s.step(time.Minute); err != nil {
		return err
	}
	if err := s.step(time.Minute); err != nil {
		return err
	}
	if err := s.step(time.Minute); err != nil {
		return err
	}
	res, err := s.doc.ApplyFix(context.Background(), "example-desktop-app", plugins.FixForceRestart, false)
	if err != nil {
		return err
	}
	s.outcome(res.Message)

	fmt.Fprintln(s.w, "")
	fmt.Fprintln(s.w, "Scene 2. The network drops. Example Sync comes back. Example Mail does not.")
	s.world.networkUp = false
	if err := s.step(time.Minute); err != nil {
		return err
	}
	s.world.mailUp = false
	if err := s.step(time.Minute); err != nil {
		return err
	}
	s.world.networkUp = true
	if err := s.step(time.Minute); err != nil {
		return err
	}
	if err := s.step(time.Minute); err != nil {
		return err
	}
	s.outcome("Example Mail stays stopped. The demo does not apply a fix.")

	fmt.Fprintln(s.w, "")
	fmt.Fprintln(s.w, "Scene 3. ExampleTool holds the CPU, then it is stopped.")
	s.world.hog = true
	if err := s.step(time.Minute); err != nil {
		return err
	}
	if err := s.step(5 * time.Minute); err != nil {
		return err
	}
	stopped, err := s.doc.ApplyStop(context.Background(), "ExampleTool", false)
	if err != nil {
		return err
	}
	s.outcome(stopped.Message)

	fmt.Fprintln(s.w, "")
	fmt.Fprintln(s.w, "Scene 4. Example Bridge fails three times in one hour.")
	if err := s.failBridge(); err != nil {
		return err
	}
	s.world.bridgeUp = true
	if err := s.step(time.Minute); err != nil {
		return err
	}
	s.note("Example Bridge is running again. No fix was applied.")
	if err := s.failBridge(); err != nil {
		return err
	}
	s.world.bridgeUp = true
	if err := s.step(time.Minute); err != nil {
		return err
	}
	s.note("Example Bridge is running again. No fix was applied.")
	return s.failBridge()
}

func (s *script) failBridge() error {
	s.world.bridgeUp = false
	if err := s.step(time.Minute); err != nil {
		return err
	}
	return s.step(time.Minute)
}

func (s *script) step(d time.Duration) error {
	s.clock.advance(d)
	s.src.Set(s.world.snapshot())
	rows, err := s.doc.Cycle(context.Background())
	if err != nil {
		return err
	}
	s.printAlerts(rows)
	return nil
}

func (s *script) printAlerts(rows []doctor.ServiceStatus) {
	for _, row := range rows {
		for _, alert := range row.Alerts {
			fmt.Fprintf(s.w, "%s  alert: %s\n", s.stamp(), alert.Message)
			fmt.Fprintf(s.w, "%s  fix offered: %s\n", s.stamp(), offer(alert))
		}
	}
}

func (s *script) outcome(msg string) {
	fmt.Fprintf(s.w, "%s  outcome: %s\n", s.stamp(), msg)
}

func (s *script) note(msg string) {
	fmt.Fprintf(s.w, "%s  note: %s\n", s.stamp(), msg)
}

func (s *script) stamp() string {
	return s.clock.t.UTC().Format("15:04") + " UTC"
}

func offer(alert rules.Alert) string {
	if !alert.OfferFix {
		return "none"
	}
	if alert.ServiceID == rules.UnwatchedID && alert.Process != "" {
		return "stop " + alert.Process
	}
	if len(alert.Actions) > 1 {
		return join(alert.Actions)
	}
	if alert.Action != "" {
		return alert.Action
	}
	return "none"
}

func join(actions []string) string {
	out := actions[0]
	for _, action := range actions[1:] {
		out += " or " + action
	}
	return out
}

func scriptPlugins() []plugins.Plugin {
	return []plugins.Plugin{
		{
			ID: "this-mac", Name: "This Mac", Host: true,
			Checks: []plugins.Check{
				{Type: plugins.CheckSleep},
				{Type: plugins.CheckNetwork},
				{Type: plugins.CheckDisk, MinFreePercent: 10},
				{Type: plugins.CheckMemory, Level: "warn", Duration: "5m"},
				{Type: plugins.CheckCPU, CPUPercent: 85, Duration: "5m"},
			},
		},
		{
			ID: "example-desktop-app", Name: "Example Desktop App",
			Process: plugins.ProcessMatch{Match: "example-desktop-app"},
			Checks: []plugins.Check{
				{Type: plugins.CheckProcessRunning},
				{Type: plugins.CheckOutboundTCP, Port: 443, Consecutive: 3},
			},
			Messages: plugins.Messages{
				Stuck: "Example Desktop App is open but has no established outbound connection on port 443, so it looks stuck.",
			},
			Fixes: map[string]plugins.Fix{
				plugins.FixForceRestart: {Kind: plugins.FixForceRestart},
			},
		},
		{
			ID: "example-sync", Name: "Example Sync",
			Process: plugins.ProcessMatch{Match: "example-sync"},
			Checks:  []plugins.Check{{Type: plugins.CheckProcessRunning}},
			Messages: plugins.Messages{
				Down: "Example Sync has stopped. It is not running.",
			},
			Fixes: map[string]plugins.Fix{
				plugins.FixRestart: {Kind: plugins.FixRestart},
			},
		},
		{
			ID: "example-mail", Name: "Example Mail",
			Process: plugins.ProcessMatch{Match: "example-mail"},
			Checks:  []plugins.Check{{Type: plugins.CheckProcessRunning}},
			Messages: plugins.Messages{
				Down: "Example Mail has stopped. It is not running.",
			},
			Fixes: map[string]plugins.Fix{
				plugins.FixRestart: {Kind: plugins.FixRestart},
			},
		},
		{
			ID: "example-bridge", Name: "Example Bridge",
			Process: plugins.ProcessMatch{Match: "example-bridge"},
			Checks:  []plugins.Check{{Type: plugins.CheckProcessRunning}},
			Messages: plugins.Messages{
				Down:           "Example Bridge has stopped. It is not running.",
				KeepsHappening: "Example Bridge has failed 3 times in the last hour. Automatic fixes are paused.",
			},
			Fixes: map[string]plugins.Fix{
				plugins.FixRestart: {Kind: plugins.FixRestart},
			},
		},
	}
}
