package sysprobe

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParsePS reads "pid ppid command" lines from ps -o pid= -o ppid= -o command=.
func ParsePS(text string) ([]Process, error) {
	var procs []Process
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, rest, ok := leadingInt(line)
		if !ok {
			return nil, fmt.Errorf("ps line has no pid: %q", line)
		}
		ppid, cmd, ok := leadingInt(rest)
		if !ok {
			return nil, fmt.Errorf("ps line has no parent pid: %q", line)
		}
		cmd = strings.TrimSpace(cmd)
		procs = append(procs, Process{
			PID:  pid,
			PPID: ppid,
			Name: filepathBase(cmd),
			Exe:  cmd,
			Cmd:  cmd,
		})
	}
	return procs, nil
}

// ParseLsofF reads lsof -F pn output and returns PID to remote ports
// for established connections that have an outbound arrow.
func ParseLsofF(text string) map[int][]int {
	out := map[int][]int{}
	pid := 0
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			n, err := strconv.Atoi(line[1:])
			if err != nil || n <= 0 {
				pid = 0
				continue
			}
			pid = n
		case 'n':
			if pid <= 0 {
				continue
			}
			port, ok := remotePort(line[1:])
			if !ok {
				continue
			}
			out[pid] = append(out[pid], port)
		}
	}
	return out
}

func remotePort(name string) (int, bool) {
	name = strings.TrimSpace(name)
	if i := strings.Index(name, " ("); i >= 0 {
		name = name[:i]
	}
	arrow := strings.LastIndex(name, "->")
	if arrow < 0 {
		return 0, false
	}
	right := name[arrow+2:]
	_, portStr, err := net.SplitHostPort(right)
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

func leadingInt(s string) (int, string, bool) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, s, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, s, false
	}
	return n, strings.TrimSpace(s[i:]), true
}

func filepathBase(path string) string {
	if path == "" {
		return ""
	}
	slash := strings.LastIndexAny(path, `/\`)
	if slash >= 0 && slash < len(path)-1 {
		return path[slash+1:]
	}
	return path
}
