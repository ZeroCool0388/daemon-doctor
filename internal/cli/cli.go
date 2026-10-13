// Package cli is the daemon-doctor command line.
package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/config"
	"github.com/ZeroCool0388/daemon-doctor/internal/control"
	"github.com/ZeroCool0388/daemon-doctor/internal/demo"
	"github.com/ZeroCool0388/daemon-doctor/internal/doctor"
	"github.com/ZeroCool0388/daemon-doctor/internal/fixes"
	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/mcpserver"
	"github.com/ZeroCool0388/daemon-doctor/internal/offers"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/rules"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

// Run executes the command in args[0] with subcommand args[1].
// It returns a process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		usage(stderr)
		return 2
	}
	switch args[1] {
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	case "status":
		return statusCmd(args[2:], stdout, stderr)
	case "run":
		return runCmd(args[2:], stdout, stderr)
	case "fix":
		return fixCmd(args[2:], stdin, stdout, stderr)
	case "pair":
		return pairCmd(args[2:], stdout, stderr)
	case "mcp-token":
		return mcpTokenCmd(args[2:], stdout, stderr)
	case "mcp":
		return mcpCmd(args[2:], stdin, stdout, stderr)
	case "demo":
		return demoCmd(args[2:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[1])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `daemon-doctor watches local apps and applies an allowlisted fix only when you say so.

Usage:
  daemon-doctor status [--config path]
  daemon-doctor run [--config path]
  daemon-doctor pair [--out path.png] [--list] [--config path]
  daemon-doctor fix --service id --action stop|restart|force-restart|launchctl_kickstart [--dry-run] [--yes] [--config path]
  daemon-doctor fix --process name --action stop [--dry-run] [--yes] [--config path]
  daemon-doctor fix --approval file [--dry-run] [--config path]
  daemon-doctor demo
  daemon-doctor mcp-token [--config path]
  daemon-doctor mcp [--config path] [--demo] [--allow-fixes]

status prints one check of each plug-in.
run repeats checks on the configured interval until interrupted.
pair prints a one-time pairing payload and a terminal QR; --out also saves a PNG.
The private key stays in the state directory.
fix applies one allowlisted action after you answer y, then rechecks.
fix --approval reads a signed phone approval. The signature is the approval.
--process stop is only for a process named by an unwatched resource alert.
--dry-run rechecks without signalling a process or launching anything.
demo replays scripted incidents with fake services. It does not use a Mac, a relay, or a phone.

The default config path is ~/.config/daemon-doctor/config.yaml.
`)
}

func demoCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "demo does not take arguments\n")
		return 2
	}
	if err := demo.Run(stdout); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func statusCmd(args []string, stdout, stderr io.Writer) int {
	path, code, ok := configFlag("status", args, stderr)
	if !ok {
		return code
	}
	d, book, _, err := openDoctor(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer book.Close()
	rows, err := d.Cycle(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	for _, row := range rows {
		fmt.Fprint(stdout, formatStatus(row))
	}
	return 0
}

func runCmd(args []string, stdout, stderr io.Writer) int {
	path, code, ok := configFlag("run", args, stderr)
	if !ok {
		return code
	}
	d, book, cfg, err := openDoctor(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer book.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.ControlEnabled || cfg.RelayMCPLink {
		store, e := offers.Open(filepath.Dir(cfg.ControlSocket))
		if e != nil {
			fmt.Fprintf(stderr, "control error: %v\n", e)
			return 1
		}
		d.UseOffers(store)
	}
	if cfg.ControlEnabled {
		server, e := control.Listen(cfg.ControlSocket, &control.Local{Doctor: d, AllowFixes: cfg.ControlAllowFixes})
		if e != nil {
			fmt.Fprintf(stderr, "control error: %v\n", e)
			return 1
		}
		defer server.Close()
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx) }()
		defer func() { stop(); server.Close(); <-done }()
	}
	if cfg.RelayMCPLink {
		sec, e := security.LoadOrCreate(cfg.StateDir)
		if e != nil {
			fmt.Fprintf(stderr, "MCP link error: %v\n", e)
			return 1
		}
		secret, e := sec.MCPLinkSecret()
		if e != nil {
			fmt.Fprintf(stderr, "MCP link error: %v\n", e)
			return 1
		}
		client, e := relay.New(cfg.RelayURL)
		if e != nil {
			fmt.Fprintf(stderr, "MCP link error: %v\n", e)
			return 1
		}
		link := &relay.MCPLink{Client: client, MacID: sec.MacID(), Secret: secret,
			Dispatch: mcpserver.RemoteDispatch(&control.Local{Doctor: d, AllowFixes: cfg.ControlAllowFixes}, cfg.ControlAllowFixes)}
		done := make(chan struct{})
		go func() { defer close(done); link.Run(ctx, func(err error) { fmt.Fprintf(stderr, "%v\n", err) }) }()
		defer func() { stop(); <-done }()
	}
	err = d.Run(ctx, cfg.Interval, func(rows []doctor.ServiceStatus) {
		for _, row := range rows {
			fmt.Fprint(stdout, formatStatus(row))
		}
	}, func(err error) {
		fmt.Fprintf(stderr, "check error: %v\n", err)
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func fixCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	service := fs.String("service", "", "plug-in id")
	processName := fs.String("process", "", "process name for an unwatched stop")
	action := fs.String("action", "", "stop, restart, force-restart, or launchctl_kickstart")
	dryRun := fs.Bool("dry-run", false, "recheck without applying the fix")
	yes := fs.Bool("yes", false, "apply the fix without a prompt")
	approvalPath := fs.String("approval", "", "path to a signed approval")
	if err := fs.Parse(args); err != nil {
		return flagCode(err)
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	path, err := resolveConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if *approvalPath != "" {
		if *service != "" || *processName != "" || *action != "" {
			fmt.Fprintln(stderr, "fix --approval does not take --service, --process, or --action")
			return 2
		}
		return fixApproval(path, *approvalPath, *dryRun, stdout, stderr)
	}
	if *processName != "" && *service != "" {
		fmt.Fprintln(stderr, "fix takes either --service or --process")
		return 2
	}
	if *processName != "" {
		if *action != plugins.FixStop {
			fmt.Fprintln(stderr, "fix --process only allows --action stop")
			return 2
		}
		return fixProcess(path, *processName, *dryRun, *yes, stdin, stdout, stderr)
	}
	if *service == "" || *action == "" {
		fmt.Fprintln(stderr, "fix needs --service and --action")
		return 2
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	ps, err := plugins.LoadDir(cfg.PluginsDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	var plug plugins.Plugin
	found := false
	for _, p := range ps {
		if p.ID == *service {
			plug = p
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(stderr, "error: no plug-in with id %q\n", *service)
		return 1
	}
	if _, ok := plugins.FixAllowlist[*action]; !ok || !plugins.Approved(plug, *action) {
		fmt.Fprintf(stderr, "error: fix %q is not approved for %s\n", *action, plug.ID)
		return 1
	}
	if !*dryRun && !*yes {
		fmt.Fprintf(stderr, "Apply %s to %s? [y/N] ", *action, plug.Name)
		if !confirmed(stdin) {
			fmt.Fprintln(stdout, "Fix not run.")
			return 0
		}
	}
	book, err := logbook.Open(cfg.LogPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer book.Close()
	d, err := doctor.New(ps, sysprobe.Live(), fixes.OSController{}, book, checks.NewRegistry(), time.Now)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	res, err := d.ApplyFix(context.Background(), *service, *action, *dryRun)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, res.Message)
	if res.Detail != "" {
		fmt.Fprintln(stdout, res.Detail)
	}
	return 0
}

func fixProcess(path, processName string, dryRun, yes bool, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := fixes.ValidProcessName(processName); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	ps, err := plugins.LoadDir(cfg.PluginsDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if !dryRun && !yes {
		fmt.Fprintf(stderr, "Apply stop to %s? [y/N] ", processName)
		if !confirmed(stdin) {
			fmt.Fprintln(stdout, "Fix not run.")
			return 0
		}
	}
	book, err := logbook.Open(cfg.LogPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer book.Close()
	d, err := doctor.New(ps, sysprobe.Live(), fixes.OSController{}, book, checks.NewRegistry(), time.Now)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	res, err := d.ApplyStop(context.Background(), processName, dryRun)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, res.Message)
	if res.Detail != "" {
		fmt.Fprintln(stdout, res.Detail)
	}
	return 0
}

func fixApproval(path, approvalPath string, dryRun bool, stdout, stderr io.Writer) int {
	raw, err := os.ReadFile(approvalPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	d, book, cfg, err := openDoctor(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer book.Close()
	sec, err := security.Open(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(stderr, "error: pair first")
		return 1
	}
	var client *relay.Client
	if cfg.RelayURL != "" {
		client, err = relay.New(cfg.RelayURL)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	}
	d.UseRelay(sec, client)
	res, err := d.ApplyApproval(context.Background(), raw, dryRun)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, res.Message)
	if res.Detail != "" {
		fmt.Fprintln(stdout, res.Detail)
	}
	return 0
}

func pairCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	list := fs.Bool("list", false, "print paired phone fingerprints")
	out := fs.String("out", "", "write the pairing QR to a new PNG file")
	if err := fs.Parse(args); err != nil {
		return flagCode(err)
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *list && *out != "" {
		fmt.Fprintln(stderr, "pair --list does not take --out")
		return 2
	}
	path, err := resolveConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if *list {
		sec, err := security.Open(cfg.StateDir)
		if err != nil {
			fmt.Fprintln(stderr, "error: pair first")
			return 1
		}
		for _, phone := range sec.Phones() {
			fmt.Fprintln(stdout, security.Fingerprint(phone))
		}
		return 0
	}
	if *out != "" {
		if _, err := os.Lstat(*out); err == nil {
			fmt.Fprintln(stderr, "error: pairing PNG already exists")
			return 1
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	}
	sec, err := security.LoadOrCreate(cfg.StateDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	payload, err := sec.BeginPairing(time.Now(), cfg.RelayURL)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "payload %s\n", payload)
	qr, err := security.QR(payload)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, qr)
	if *out != "" {
		if err := security.WriteQRPNG(payload, *out); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "QR saved to %s\n", *out)
	}
	if cfg.RelayURL == "" {
		return 0
	}
	client, err := relay.New(cfg.RelayURL)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, security.PairingTTL)
	defer cancel()
	deadline := time.Now().Add(security.PairingTTL)
	for {
		if !time.Now().Before(deadline) {
			fmt.Fprintln(stderr, "error: pairing code expired")
			return 1
		}
		events, err := client.Poll(ctx, sec.MacID(), "pairing")
		if err != nil {
			if ctx.Err() != nil {
				if signalCtx.Err() == nil {
					fmt.Fprintln(stderr, "error: pairing code expired")
					return 1
				}
				return 0
			}
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		for _, event := range events {
			pairing, err := security.UnmarshalPairing(event.Body)
			if err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				continue
			}
			if err := sec.AcceptPairing(time.Now(), pairing); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				continue
			}
			fmt.Fprintf(stdout, "paired %s\n", security.Fingerprint(pairing.PublicKey))
			return 0
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			if signalCtx.Err() == nil {
				fmt.Fprintln(stderr, "error: pairing code expired")
				return 1
			}
			return 0
		case <-timer.C:
		}
	}
}

func configFlag(name string, args []string, stderr io.Writer) (string, int, bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return "", 0, false
		}
		return "", 2, false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return "", 2, false
	}
	path, err := resolveConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return "", 1, false
	}
	return path, 0, true
}

func resolveConfig(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("config path: %w", err)
	}
	return filepath.Join(home, ".config", "daemon-doctor", "config.yaml"), nil
}

func flagCode(err error) int {
	if err == flag.ErrHelp {
		return 0
	}
	if err != nil && strings.HasPrefix(err.Error(), "unexpected argument") {
		return 2
	}
	if err == nil {
		return 0
	}
	return 2
}

func confirmed(r io.Reader) bool {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	line = strings.TrimSpace(line)
	return line == "y" || line == "Y"
}

func openDoctor(path string) (*doctor.Doctor, *logbook.Book, config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, config.Config{}, err
	}
	ps, err := plugins.LoadDir(cfg.PluginsDir)
	if err != nil {
		return nil, nil, config.Config{}, err
	}
	if len(ps) == 0 {
		return nil, nil, config.Config{}, fmt.Errorf("no plug-ins in %s", cfg.PluginsDir)
	}
	book, err := logbook.Open(cfg.LogPath)
	if err != nil {
		return nil, nil, config.Config{}, err
	}
	d, err := doctor.New(ps, sysprobe.Live(), fixes.OSController{}, book, checks.NewRegistry(), time.Now)
	if err != nil {
		book.Close()
		return nil, nil, config.Config{}, err
	}
	if err := attachRelay(d, cfg); err != nil {
		book.Close()
		return nil, nil, config.Config{}, err
	}
	return d, book, cfg, nil
}

func attachRelay(d *doctor.Doctor, cfg config.Config) error {
	if cfg.RelayURL == "" {
		sec, err := security.Open(cfg.StateDir)
		if err != nil {
			return nil
		}
		d.UseRelay(sec, nil)
		return nil
	}
	var sec *security.Store
	var err error
	if cfg.RelayMCPLink {
		sec, err = security.LoadOrCreate(cfg.StateDir)
	} else {
		sec, err = security.Open(cfg.StateDir)
	}
	if err != nil {
		return fmt.Errorf("Mac identity: %w", err)
	}
	client, err := relay.New(cfg.RelayURL)
	if err != nil {
		return err
	}
	d.UseRelay(sec, client)
	return nil
}

func formatStatus(st doctor.ServiceStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s): %s\n", st.ID, st.Name, statusText(st.Status))
	for _, outcome := range st.Outcomes {
		if outcome.Detail != "" {
			fmt.Fprintf(&b, "  %s\n", outcome.Detail)
		}
	}
	for _, alert := range st.Alerts {
		fmt.Fprintf(&b, "  alert: %s\n", alert.Message)
		if alert.OfferFix {
			fmt.Fprintf(&b, "  fix offered: %s\n", offerText(st.ID, alert))
		} else {
			fmt.Fprintf(&b, "  fix offered: none\n")
		}
	}
	return b.String()
}

func offerText(rowID string, alert rules.Alert) string {
	if alert.ServiceID == rules.UnwatchedID && alert.Process != "" {
		return "stop --process " + alert.Process
	}
	action := alert.Action
	if len(alert.Actions) > 1 {
		action = strings.Join(alert.Actions, " or ")
	}
	if action == "" {
		return "none"
	}
	if alert.ServiceID != "" && alert.ServiceID != rowID {
		return action + " --service " + alert.ServiceID
	}
	return action
}

func statusText(status string) string {
	switch status {
	case rules.StatusOK:
		return "ok"
	case rules.StatusPending:
		return "not running (waiting for a second check before alerting)"
	case rules.StatusWatch:
		return "running, health signal missed (not stuck yet)"
	case rules.StatusDown:
		return "down"
	case rules.StatusStuck:
		return "running but stuck"
	case rules.StatusHeld:
		return "paused"
	default:
		return status
	}
}

func mcpCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	demoMode := fs.Bool("demo", false, "use only scripted fake incidents")
	allow := fs.Bool("allow-fixes", false, "enable fixes; requires per-call host approval and daemon opt-in")
	if err := fs.Parse(args); err != nil {
		return flagCode(err)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "mcp does not take positional arguments")
		return 2
	}
	if *demoMode && *configPath != "" {
		fmt.Fprintln(stderr, "mcp --demo does not use --config")
		return 2
	}
	var backend control.Backend
	if *demoMode {
		b, err := demo.NewMCP()
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		backend = b
	} else {
		path, err := resolveConfig(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		cfg, err := config.Load(path)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		if !cfg.ControlEnabled {
			fmt.Fprintln(stderr, "error: daemon control socket is disabled in config")
			return 1
		}
		backend = &control.Client{Path: cfg.ControlSocket}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := mcpserver.Serve(ctx, backend, *allow || *demoMode, stdin, stdout); err != nil && ctx.Err() == nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}
