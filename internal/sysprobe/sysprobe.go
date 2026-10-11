// Package sysprobe reads process and TCP state through a Source interface
// so checks can be tested without touching a live system.
package sysprobe

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
)

// Process is one running process.
type Process struct {
	PID  int
	PPID int
	Name string // kernel command name
	Exe  string // argv0, when known
	Cmd  string // command line for display; checks match on Name and Exe
}

// Snapshot is one sample of processes and their established outbound TCP ports.
// OutboundPorts maps a PID to the remote ports of its established outbound connections.
type Snapshot struct {
	Processes     []Process
	OutboundPorts map[int][]int
}

// Source takes a sample. Live system calls sit behind this interface.
type Source interface {
	Take(ctx context.Context) (Snapshot, error)
}

// MemSource returns a snapshot set by the caller. Tests use it in place of a live system.
type MemSource struct {
	mu      sync.Mutex
	Current Snapshot
	Err     error
	Takes   int
}

// Set replaces the snapshot returned by later Take calls.
func (m *MemSource) Set(s Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Current = s
}

// Take returns the current snapshot.
func (m *MemSource) Take(context.Context) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Takes++
	if m.Err != nil {
		return Snapshot{}, m.Err
	}
	return clone(m.Current), nil
}

// ScriptSource returns snapshots in order, then keeps returning the last one.
type ScriptSource struct {
	mu    sync.Mutex
	Snaps []Snapshot
	Err   error
	i     int
	Takes int
}

// Take returns the next snapshot.
func (s *ScriptSource) Take(context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Takes++
	if s.Err != nil {
		return Snapshot{}, s.Err
	}
	if len(s.Snaps) == 0 {
		return Snapshot{}, errNoSnapshot
	}
	idx := s.i
	if idx >= len(s.Snaps) {
		idx = len(s.Snaps) - 1
	} else {
		s.i++
	}
	return clone(s.Snaps[idx]), nil
}

type noSnapshotError struct{}

func (noSnapshotError) Error() string { return "no snapshot" }

var errNoSnapshot = noSnapshotError{}

func clone(s Snapshot) Snapshot {
	out := Snapshot{
		Processes:     append([]Process(nil), s.Processes...),
		OutboundPorts: make(map[int][]int, len(s.OutboundPorts)),
	}
	for pid, ports := range s.OutboundPorts {
		out.OutboundPorts[pid] = append([]int(nil), ports...)
	}
	return out
}

// Matches reports whether p is the process named by match.
// match is compared with the process name, the executable, and the executable base name.
func Matches(p Process, match string) bool {
	if match == "" {
		return false
	}
	if p.Name == match || p.Exe == match || p.Cmd == match {
		return true
	}
	if p.Exe != "" && filepath.Base(p.Exe) == match {
		return true
	}
	return false
}

// Matching returns processes in s that match, ordered by PID.
func Matching(s Snapshot, match string) []Process {
	var found []Process
	for _, p := range s.Processes {
		if Matches(p, match) {
			found = append(found, p)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].PID < found[j].PID })
	return found
}

// RootPIDs returns the PIDs of processes that match.
func RootPIDs(s Snapshot, match string) []int {
	found := Matching(s, match)
	ids := make([]int, len(found))
	for i, p := range found {
		ids[i] = p.PID
	}
	return ids
}

// SignalOrder returns roots and their descendants, children before parents.
// A process is visited once. PID values below 1 are dropped.
func SignalOrder(s Snapshot, roots []int) []int {
	if len(roots) == 0 {
		return nil
	}
	children := map[int][]int{}
	ppid := map[int]int{}
	for _, p := range s.Processes {
		ppid[p.PID] = p.PPID
		if p.PID <= 0 {
			continue
		}
		children[p.PPID] = append(children[p.PPID], p.PID)
	}
	for parent := range children {
		sort.Ints(children[parent])
	}
	rootSet := map[int]struct{}{}
	for _, id := range roots {
		if id > 0 {
			rootSet[id] = struct{}{}
		}
	}
	var tops []int
	for id := range rootSet {
		if !ancestorIn(id, rootSet, ppid) {
			tops = append(tops, id)
		}
	}
	sort.Ints(tops)
	seen := map[int]struct{}{}
	var out []int
	var walk func(int)
	walk = func(pid int) {
		if pid <= 0 {
			return
		}
		if _, ok := seen[pid]; ok {
			return
		}
		seen[pid] = struct{}{}
		for _, child := range children[pid] {
			walk(child)
		}
		out = append(out, pid)
	}
	for _, id := range tops {
		walk(id)
	}
	return out
}

func ancestorIn(pid int, set map[int]struct{}, ppid map[int]int) bool {
	seen := map[int]struct{}{}
	cur := ppid[pid]
	for cur > 0 {
		if _, ok := seen[cur]; ok {
			return false
		}
		seen[cur] = struct{}{}
		if _, ok := set[cur]; ok {
			return true
		}
		cur = ppid[cur]
	}
	return false
}

// CountOutbound counts established outbound TCP connections to port
// from roots and their descendants.
func CountOutbound(s Snapshot, roots []int, port int) int {
	pids := SignalOrder(s, roots)
	if len(pids) == 0 {
		return 0
	}
	want := map[int]struct{}{}
	for _, pid := range pids {
		want[pid] = struct{}{}
	}
	n := 0
	for pid := range want {
		for _, remote := range s.OutboundPorts[pid] {
			if remote == port {
				n++
			}
		}
	}
	return n
}
