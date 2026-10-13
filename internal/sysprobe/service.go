package sysprobe

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func readSystemServices(ctx context.Context, hints []ServiceHint) map[ServiceHint]ServiceState {
	out := make(map[ServiceHint]ServiceState, len(hints))
	for _, hint := range hints {
		loaded, loadKnown := systemServiceLoaded(ctx, hint.Label)
		state := ServiceState{Loaded: loaded, Known: loaded}
		if !loaded {
			listening, listenKnown := tcpListening(ctx, hint.Port)
			state.Listening = listening
			state.Known = listening || (loadKnown && listenKnown)
		}
		out[hint] = state
	}
	return out
}

// A registered service is available on demand only when its disabled policy
// can be read and does not disable it. Failed policy reads remain unknown.
func systemServiceLoaded(ctx context.Context, label string) (loaded, known bool) {
	cctx, cancel := context.WithTimeout(ctx, hostReadTimeout)
	defer cancel()
	_, err := exec.CommandContext(cctx, "launchctl", "print", "system/"+label).Output()
	if err == nil {
		disabled, known := systemServiceDisabled(ctx, label)
		return known && !disabled, known
	}
	if cctx.Err() != nil {
		return false, false
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && strings.Contains(strings.ToLower(string(exitErr.Stderr)), "could not find service") {
		return false, true
	}
	return false, false
}

func systemServiceDisabled(ctx context.Context, label string) (disabled, known bool) {
	cctx, cancel := context.WithTimeout(ctx, hostReadTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "launchctl", "print-disabled", "system").Output()
	if err != nil || cctx.Err() != nil {
		return false, false
	}
	return parseLaunchdDisabled(string(out), label)
}

// An absent override in a readable dictionary does not disable a registered
// service. Match quoted labels exactly so another service's policy cannot apply.
func parseLaunchdDisabled(text, label string) (disabled, known bool) {
	header, body, ok := strings.Cut(strings.TrimSpace(text), "{")
	if !ok || strings.TrimSpace(header) != "disabled services =" {
		return false, false
	}
	body, ok = strings.CutSuffix(strings.TrimSpace(body), "}")
	if !ok {
		return false, false
	}
	found := false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=>")
		if !ok {
			return false, false
		}
		key, err := strconv.Unquote(strings.TrimSpace(key))
		if err != nil {
			return false, false
		}
		var policy bool
		switch strings.TrimSpace(value) {
		case "true", "disabled":
			policy = true
		case "false", "enabled":
			policy = false
		default:
			return false, false
		}
		if key == label {
			if found {
				return false, false
			}
			disabled, found = policy, true
		}
	}
	return disabled, true
}

// Inspect listening sockets without opening a connection that could activate
// the service. -a combines the port and LISTEN filters instead of ORing them.
func tcpListening(ctx context.Context, port int) (listening, known bool) {
	cctx, cancel := context.WithTimeout(ctx, hostReadTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "lsof", "-nP", "-a", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-F", "n").Output()
	if cctx.Err() != nil {
		return false, false
	}
	if err != nil {
		var exitErr *exec.ExitError
		// lsof exits 1 when the selection contains no sockets. Diagnostic
		// output instead indicates a failed read, not a closed port.
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && len(out) == 0 && len(exitErr.Stderr) == 0 {
			return false, true
		}
		return false, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "n") || strings.Contains(line, "->") {
			continue
		}
		_, rawPort, err := net.SplitHostPort(strings.TrimSpace(line[1:]))
		if err == nil && rawPort == strconv.Itoa(port) {
			return true, true
		}
	}
	return false, true
}
