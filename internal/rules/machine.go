package rules

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

const memoryRecoveryGrace = 3 * time.Minute

// Sample is one plug-in's checks for the current snapshot.
type Sample struct {
	Plugin   plugins.Plugin
	Outcomes []checks.Outcome
}

// MachineVerdict is the host decision for one sample.
// Hold means service alerts stay paused and their streaks are left unchanged.
type MachineVerdict struct {
	Hold   bool
	Alerts []Alert
	// Normal lists machine conditions with a confirmed healthy reading.
	// Unknown readings and held resource checks never clear an incident.
	Normal []string
}

// HostHold reports whether service alerts should pause.
// An unknown sleep or network reading does not pause anything.
func HostHold(p plugins.Plugin, h sysprobe.Host) bool {
	if !p.Host {
		return false
	}
	if _, ok := checkByType(p, plugins.CheckSleep); ok && h.SleepKnown && h.Asleep {
		return true
	}
	if _, ok := checkByType(p, plugins.CheckNetwork); ok && h.NetworkKnown && !h.NetworkUp {
		return true
	}
	return false
}

// DecideMachine applies sleep, network, disk, and sustained resource rules.
// A zero host reading leaves that rule quiet. With no host plug-in, the verdict is empty.
func (e *Engine) DecideMachine(now time.Time, snap sysprobe.Snapshot, samples []Sample) MachineVerdict {
	host, ok := hostFrom(samples)
	if !ok {
		return MachineVerdict{}
	}
	st := e.machine()
	now = now.UTC()
	var alerts []Alert
	h := snap.Host

	alerts = append(alerts, st.observeSleep(host, h, now)...)
	alerts = append(alerts, st.observeNetwork(host, h, now)...)

	hold := HostHold(host, h)
	if st.networkBackPending && !hold {
		st.networkBackPending = false
		alerts = append(alerts, networkBackAlert(host, samples, now))
	}
	if hold {
		// Paused checks cannot confirm continuously low memory pressure.
		st.mem.recovering = false
		return MachineVerdict{Hold: true, Alerts: alerts}
	}

	verdict := MachineVerdict{Alerts: alerts}
	disk, diskNormal := st.observeDisk(host, h, now)
	cpu, cpuNormal := st.observeCPU(host, snap, samples, now)
	mem, memNormal := st.observeMemory(host, snap, samples, now)
	verdict.Alerts = append(verdict.Alerts, disk...)
	verdict.Alerts = append(verdict.Alerts, cpu...)
	verdict.Alerts = append(verdict.Alerts, mem...)
	if diskNormal {
		verdict.Normal = append(verdict.Normal, KindDiskLow)
	}
	if cpuNormal {
		verdict.Normal = append(verdict.Normal, KindCPUHog)
	}
	if memNormal {
		verdict.Normal = append(verdict.Normal, KindMemoryHog)
	}
	st.syncStop()
	return verdict
}

// StopAllowed reports whether name is the process a current unwatched hog alert named.
func (e *Engine) StopAllowed(name string) bool {
	if e.mac == nil || e.mac.stopAllowed == nil {
		return false
	}
	_, ok := e.mac.stopAllowed[strings.TrimSpace(name)]
	return ok
}

type machineState struct {
	sawSleep           bool
	asleep             bool
	sleepActive        bool
	sawNetwork         bool
	networkUp          bool
	networkActive      bool
	networkBackPending bool
	diskActive         bool
	cpu                hogWatch
	mem                memoryWatch
	stopAllowed        map[string]struct{}
}

type hogWatch struct {
	started bool
	active  bool
	watched bool
	since   time.Time
	pid     int
	name    string
}

// Memory pressure belongs to the machine. Process attribution is captured only
// when the alert fires, and only that current process remains eligible for fixes.
type memoryWatch struct {
	hogWatch
	recovering  bool
	belowSince  time.Time
	fixEligible bool
	serviceID   string
}

func (e *Engine) machine() *machineState {
	if e.mac == nil {
		e.mac = &machineState{}
	}
	return e.mac
}

func hostFrom(samples []Sample) (plugins.Plugin, bool) {
	for _, sample := range samples {
		if sample.Plugin.Host {
			return sample.Plugin, true
		}
	}
	return plugins.Plugin{}, false
}

func checkByType(p plugins.Plugin, typ string) (plugins.Check, bool) {
	for _, check := range p.Checks {
		if check.Type == typ {
			return check, true
		}
	}
	return plugins.Check{}, false
}

func (st *machineState) observeSleep(host plugins.Plugin, h sysprobe.Host, now time.Time) []Alert {
	if _, ok := checkByType(host, plugins.CheckSleep); !ok || !h.SleepKnown {
		return nil
	}
	if !st.sawSleep {
		st.sawSleep = true
		st.asleep = h.Asleep
		if h.Asleep {
			st.sleepActive = true
			return []Alert{hostAlert(host, KindSleep, nil, now)}
		}
		return nil
	}
	if h.Asleep == st.asleep {
		return nil
	}
	st.asleep = h.Asleep
	if h.Asleep {
		st.sleepActive = true
		return []Alert{hostAlert(host, KindSleep, nil, now)}
	}
	st.sleepActive = false
	return []Alert{hostAlert(host, KindWake, nil, now)}
}

func (st *machineState) observeNetwork(host plugins.Plugin, h sysprobe.Host, now time.Time) []Alert {
	if _, ok := checkByType(host, plugins.CheckNetwork); !ok || !h.NetworkKnown {
		return nil
	}
	if !st.sawNetwork {
		st.sawNetwork = true
		st.networkUp = h.NetworkUp
		if !h.NetworkUp {
			st.networkActive = true
			return []Alert{hostAlert(host, KindNetworkDown, map[string]string{"time": formatClock(now)}, now)}
		}
		return nil
	}
	if h.NetworkUp == st.networkUp {
		return nil
	}
	st.networkUp = h.NetworkUp
	if !h.NetworkUp {
		st.networkActive = true
		st.networkBackPending = false
		return []Alert{hostAlert(host, KindNetworkDown, map[string]string{"time": formatClock(now)}, now)}
	}
	st.networkActive = false
	st.networkBackPending = true
	return nil
}

func (st *machineState) observeDisk(host plugins.Plugin, h sysprobe.Host, now time.Time) ([]Alert, bool) {
	spec, ok := checkByType(host, plugins.CheckDisk)
	if !ok || !h.DiskKnown {
		return nil, false
	}
	if h.DiskFreePercent < spec.MinFreePercent {
		if st.diskActive {
			return nil, false
		}
		st.diskActive = true
		return []Alert{hostAlert(host, KindDiskLow, map[string]string{"free": formatPercent(h.DiskFreePercent)}, now)}, false
	}
	st.diskActive = false
	return nil, true
}

func (st *machineState) observeCPU(host plugins.Plugin, snap sysprobe.Snapshot, samples []Sample, now time.Time) ([]Alert, bool) {
	spec, ok := checkByType(host, plugins.CheckCPU)
	if !ok {
		return nil, false
	}
	dur, ok := positiveDuration(spec.Duration)
	if !ok {
		return nil, false
	}
	line := spec.CPUPercent
	if line <= 0 {
		line = plugins.DefaultCPUPercent
	}
	top, found := sysprobe.TopCPU(snap)
	if !found || top.CPUPercent < line {
		st.cpu = hogWatch{}
		return nil, found
	}
	return st.sustain(&st.cpu, top, samples, host, now, dur, KindCPUHog, map[string]string{
		"percent": formatPercent(top.CPUPercent),
	}), false
}

func (st *machineState) observeMemory(host plugins.Plugin, snap sysprobe.Snapshot, samples []Sample, now time.Time) ([]Alert, bool) {
	spec, ok := checkByType(host, plugins.CheckMemory)
	if !ok {
		return nil, false
	}
	w := &st.mem
	level := pressureRank(snap.Host.MemoryPressure)
	if !snap.Host.MemoryPressureKnown || level < 0 {
		w.recovering = false
		w.fixEligible = false
		return nil, false
	}
	want := spec.Level
	if want == "" {
		want = plugins.DefaultMemoryLevel
	}
	if pressureRank(want) < 1 {
		return nil, false
	}
	if level < pressureRank(want) {
		w.fixEligible = false
		if !w.started {
			return nil, false
		}
		if !w.recovering {
			w.recovering = true
			w.belowSince = now
		}
		if now.Sub(w.belowSince) < memoryRecoveryGrace {
			return nil, false
		}
		wasActive := w.active
		*w = memoryWatch{}
		return nil, wasActive
	}
	w.recovering = false
	dur, ok := positiveDuration(spec.Duration)
	if !ok {
		return nil, false
	}
	if !w.started {
		w.started = true
		w.since = now
	}
	top, found := sysprobe.TopMemory(snap)
	watched, service := watchedPlugin(samples, top)
	serviceID := UnwatchedID
	if watched {
		serviceID = service.ID
	}
	if w.active {
		w.fixEligible = found && w.pid == top.PID && w.name == sysprobe.DisplayName(top) && w.serviceID == serviceID
		return nil, false
	}
	// Keep the current above-threshold attribution even before the duration
	// elapses, for validating a saved incident in a standalone approval command.
	w.fixEligible = found
	w.pid, w.name, w.watched, w.serviceID = 0, "", false, ""
	if found {
		w.pid, w.name, w.watched, w.serviceID = top.PID, sysprobe.DisplayName(top), watched, serviceID
	}
	if now.Sub(w.since) < dur {
		return nil, false
	}
	w.active = true
	fields := map[string]string{
		"duration": formatDuration(now.Sub(w.since)),
		"level":    pressureWord(snap.Host.MemoryPressure),
	}
	if !found {
		return []Alert{{
			ServiceID: host.ID, ServiceName: host.Name, Kind: KindMemoryHog, At: now,
			Message: fill("Memory pressure has stayed at {level} for {duration}.", fields),
		}}, false
	}
	fields["process"] = w.name
	if watched {
		fields["name"] = service.Name
		return []Alert{serviceHogAlert(service, host, KindMemoryHog, fields, now)}, false
	}
	fields["name"] = w.name
	return []Alert{unwatchedHogAlert(host, KindMemoryHog, w.name, fields, now)}, false
}

func (st *machineState) sustain(w *hogWatch, top sysprobe.Process, samples []Sample, host plugins.Plugin, now time.Time, dur time.Duration, kind string, extra map[string]string) []Alert {
	name := sysprobe.DisplayName(top)
	if !w.started || w.pid != top.PID {
		*w = hogWatch{started: true, since: now, pid: top.PID, name: name}
	}
	w.name = name
	watched, service := watchedPlugin(samples, top)
	w.watched = watched
	if w.active || now.Sub(w.since) < dur {
		return nil
	}
	w.active = true
	fields := map[string]string{
		"process":  name,
		"duration": formatDuration(now.Sub(w.since)),
	}
	for key, value := range extra {
		fields[key] = value
	}
	if watched {
		fields["name"] = service.Name
		return []Alert{serviceHogAlert(service, host, kind, fields, now)}
	}
	fields["name"] = name
	return []Alert{unwatchedHogAlert(host, kind, name, fields, now)}
}

func (st *machineState) syncStop() {
	next := map[string]struct{}{}
	if st.cpu.active && !st.cpu.watched && st.cpu.name != "" {
		next[st.cpu.name] = struct{}{}
	}
	if st.mem.active && st.mem.fixEligible && !st.mem.watched && st.mem.name != "" {
		next[st.mem.name] = struct{}{}
	}
	st.stopAllowed = next
}

func pressureRank(level string) int {
	switch level {
	case "warn":
		return 1
	case "critical":
		return 2
	case "normal":
		return 0
	default:
		return -1
	}
}

func positiveDuration(raw string) (time.Duration, bool) {
	if raw == "" {
		raw = plugins.DefaultDuration.String()
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

func watchedPlugin(samples []Sample, proc sysprobe.Process) (bool, plugins.Plugin) {
	for _, sample := range samples {
		if sample.Plugin.Host {
			continue
		}
		if sysprobe.MatchesSpec(proc, sample.Plugin.Process.Spec()) {
			return true, sample.Plugin
		}
	}
	return false, plugins.Plugin{}
}

func hostAlert(host plugins.Plugin, kind string, fields map[string]string, now time.Time) Alert {
	if fields == nil {
		fields = map[string]string{}
	}
	fields["name"] = host.Name
	return Alert{
		ServiceID:   host.ID,
		ServiceName: host.Name,
		Kind:        kind,
		Message:     fill(templateFor(host.Messages, kind), fields),
		At:          now,
	}
}

func networkBackAlert(host plugins.Plugin, samples []Sample, now time.Time) Alert {
	online, offline := summarizeSamples(samples)
	fields := map[string]string{
		"name":  host.Name,
		"time":  formatClock(now),
		"ok":    strconv.Itoa(len(online)),
		"total": strconv.Itoa(len(online) + len(offline)),
	}
	msg := fill(templateFor(host.Messages, KindNetworkBack), fields)
	if len(offline) > 0 {
		msg += "\nOffline:\n• " + strings.Join(offline, "\n• ")
	}
	if len(online) > 0 {
		msg += "\nOnline:\n• " + strings.Join(online, "\n• ")
	}
	return Alert{
		ServiceID:   host.ID,
		ServiceName: host.Name,
		Kind:        KindNetworkBack,
		Message:     msg,
		At:          now,
	}
}

func serviceHogAlert(service, host plugins.Plugin, kind string, fields map[string]string, now time.Time) Alert {
	messages := service.Messages
	if templateFor(messages, kind) == defaultTemplate(kind) && templateFor(host.Messages, kind) != defaultTemplate(kind) {
		messages = host.Messages
	}
	actions := hogActions(service)
	action := ""
	offer := len(actions) > 0
	if offer {
		action = actions[0]
	}
	return Alert{
		ServiceID:   service.ID,
		ServiceName: service.Name,
		Kind:        kind,
		Message:     fill(templateFor(messages, kind), fields),
		OfferFix:    offer,
		Action:      action,
		Actions:     actions,
		Process:     fields["process"],
		At:          now,
	}
}

func unwatchedHogAlert(host plugins.Plugin, kind, process string, fields map[string]string, now time.Time) Alert {
	return Alert{
		ServiceID:   UnwatchedID,
		ServiceName: host.Name,
		Kind:        kind,
		Message:     fill(templateFor(host.Messages, kind+"_unwatched"), fields),
		OfferFix:    true,
		Action:      plugins.FixStop,
		Actions:     []string{plugins.FixStop},
		Process:     process,
		At:          now,
	}
}

func hogActions(p plugins.Plugin) []string {
	var actions []string
	if plugins.Approved(p, plugins.FixStop) {
		actions = append(actions, plugins.FixStop)
	}
	if plugins.Approved(p, plugins.FixRestart) {
		actions = append(actions, plugins.FixRestart)
	}
	return actions
}

func summarizeSamples(samples []Sample) (online, offline []string) {
	for _, sample := range samples {
		if checks.AllHealthy(sample.Outcomes) {
			online = append(online, sample.Plugin.Name)
		} else {
			offline = append(offline, sample.Plugin.Name)
		}
	}
	sort.Strings(online)
	sort.Strings(offline)
	return online, offline
}
