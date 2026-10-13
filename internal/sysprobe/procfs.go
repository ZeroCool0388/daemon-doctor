package sysprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// EstablishedTCP is the Linux TCP state for an established connection.
const EstablishedTCP = "01"

// ReadProc builds a Snapshot from a procfs-style directory (normally /proc).
// Socket inodes the current user cannot read are skipped.
func ReadProc(root string) (Snapshot, error) {
	ports, err := readEstablishedPorts(root)
	if err != nil {
		return Snapshot{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read %s: %w", root, err)
	}
	snap := Snapshot{OutboundPorts: map[int][]int{}}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		proc, err := readProcess(root, pid)
		if err != nil {
			continue
		}
		snap.Processes = append(snap.Processes, proc)
		for _, inode := range readSocketInodes(filepath.Join(root, entry.Name(), "fd")) {
			if port, ok := ports[inode]; ok {
				snap.OutboundPorts[pid] = append(snap.OutboundPorts[pid], port)
			}
		}
	}
	sort.Slice(snap.Processes, func(i, j int) bool { return snap.Processes[i].PID < snap.Processes[j].PID })
	return snap, nil
}

func readEstablishedPorts(root string) (map[string]int, error) {
	ports := map[string]int{}
	tcpPath := filepath.Join(root, "net", "tcp")
	if err := mergePortFile(ports, tcpPath, true); err != nil {
		return nil, err
	}
	tcp6Path := filepath.Join(root, "net", "tcp6")
	if err := mergePortFile(ports, tcp6Path, false); err != nil {
		return nil, err
	}
	return ports, nil
}

func mergePortFile(dst map[string]int, path string, required bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return nil
		}
		if required {
			return fmt.Errorf("read %s: %w", path, err)
		}
		return nil
	}
	for inode, port := range parseProcNet(string(data)) {
		dst[inode] = port
	}
	return nil
}

// parseProcNet reads /proc/net/tcp or tcp6 text.
// It returns socket inode to remote port for established connections only.
func parseProcNet(text string) map[string]int {
	out := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || strings.HasPrefix(fields[0], "sl") {
			continue
		}
		if fields[3] != EstablishedTCP {
			continue
		}
		port, ok := hexPort(fields[2])
		if !ok {
			continue
		}
		out[fields[9]] = port
	}
	return out
}

func hexPort(addr string) (int, bool) {
	colon := strings.LastIndex(addr, ":")
	if colon < 0 || colon == len(addr)-1 {
		return 0, false
	}
	port, err := strconv.ParseInt(addr[colon+1:], 16, 32)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return int(port), true
}

func readProcess(root string, pid int) (Process, error) {
	statRaw, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return Process{}, err
	}
	name, ppid, err := parseStat(string(statRaw))
	if err != nil {
		return Process{}, err
	}
	cmdRaw, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "cmdline"))
	exe := ""
	cmd := ""
	if err == nil {
		parts := splitCmdline(cmdRaw)
		if len(parts) > 0 {
			exe = parts[0]
			cmd = strings.Join(parts, " ")
		}
	}
	proc := Process{PID: pid, PPID: ppid, Name: name, Exe: exe, Cmd: cmd}
	proc.StartTime = parsePIDStartTime(string(statRaw))
	if statm, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "statm")); err == nil {
		if pages, ok := parseStatmResident(string(statm)); ok {
			proc.MemoryKnown = true
			proc.MemoryBytes = pages * int64(os.Getpagesize())
		}
	}
	return proc, nil
}

// parseStat reads "pid (comm) state ppid ..." from /proc/pid/stat.
func parseStat(text string) (name string, ppid int, err error) {
	text = strings.TrimSpace(text)
	open := strings.Index(text, "(")
	close := strings.LastIndex(text, ")")
	if open < 0 || close < 0 || close < open {
		return "", 0, fmt.Errorf("unrecognized stat line")
	}
	name = text[open+1 : close]
	rest := strings.Fields(text[close+1:])
	if len(rest) < 2 {
		return "", 0, fmt.Errorf("stat line is missing the parent pid")
	}
	ppid, err = strconv.Atoi(rest[1])
	if err != nil {
		return "", 0, fmt.Errorf("stat parent pid: %w", err)
	}
	return name, ppid, nil
}

// /proc/pid/stat field 22 is the start time in clock ticks since boot.
// The command in parentheses can itself contain spaces and parentheses.
func parsePIDStartTime(text string) uint64 {
	close := strings.LastIndex(text, ")")
	if close < 0 {
		return 0
	}
	fields := strings.Fields(text[close+1:]) // starts at field 3 (state)
	if len(fields) < 20 {
		return 0
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return start
}

func splitCmdline(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimRight(string(raw), "\x00")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\x00")
}

func readSocketInodes(fdDir string) []string {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var inodes []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if inode, ok := socketInode(target); ok {
			inodes = append(inodes, inode)
		}
	}
	return inodes
}

func socketInode(link string) (string, bool) {
	const prefix = "socket:["
	if strings.HasPrefix(link, prefix) && strings.HasSuffix(link, "]") {
		inode := link[len(prefix) : len(link)-1]
		if inode != "" {
			return inode, true
		}
	}
	return "", false
}
