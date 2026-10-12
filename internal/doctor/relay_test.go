package doctor

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay"
	"github.com/ZeroCool0388/daemon-doctor/internal/relay/relaytest"
	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

const exampleLauncher = "/opt/example/launch-example-desktop-app"

const launcherPluginYAML = `id: example-desktop-app
name: Example Desktop App
process:
  match: example-desktop-app
checks:
  - type: process_running
  - type: outbound_tcp
    port: 443
    consecutive: 3
messages:
  down: "Example Desktop App has stopped. It is not running."
fixes:
  restart:
    kind: restart
    launcher: ` + exampleLauncher + `
`

type launchCall struct {
	path string
	args []string
}

// healer records fix calls and brings the fake service back on launch.
type healer struct {
	mu       sync.Mutex
	src      *sysprobe.MemSource
	signals  int
	launches []launchCall
}

func (h *healer) Signal(int, syscall.Signal) error {
	h.mu.Lock()
	h.signals++
	h.mu.Unlock()
	return nil
}

func (h *healer) Launch(_ context.Context, path string, args []string) error {
	h.mu.Lock()
	h.launches = append(h.launches, launchCall{path: path, args: append([]string(nil), args...)})
	h.mu.Unlock()
	h.src.Set(running(2))
	return nil
}

func (h *healer) calls() (int, []launchCall) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.signals, append([]launchCall(nil), h.launches...)
}

type relayRig struct {
	t      *testing.T
	dir    string
	now    time.Time
	fake   *relaytest.Relay
	mac    *security.Store
	phone  ed25519.PrivateKey
	plug   plugins.Plugin
	src    *sysprobe.MemSource
	ctrl   *healer
	book   *logbook.Book
	client *relay.Client
	d      *Doctor
}

func newRelayRig(t *testing.T) *relayRig {
	t.Helper()
	r := &relayRig{t: t, dir: t.TempDir(), now: time.Now().UTC().Truncate(time.Second)}
	r.fake = relaytest.New()
	t.Cleanup(r.fake.Close)
	r.mac, r.phone = pairMac(t, r.dir, r.now)
	path := filepath.Join(r.dir, "example-desktop-app.yaml")
	if err := os.WriteFile(path, []byte(launcherPluginYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	plug, err := plugins.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r.plug = plug
	r.src = &sysprobe.MemSource{}
	r.src.Set(running(2))
	r.ctrl = &healer{src: r.src}
	r.book = openBook(t, r.dir)
	r.d, r.client = r.doctor(true)
	return r
}

// doctor builds a doctor on the shared state directory, as a restart would.
func (r *relayRig) doctor(keepCursor bool) (*Doctor, *relay.Client) {
	r.t.Helper()
	d, err := New([]plugins.Plugin{r.plug}, r.src, r.ctrl, r.book, nil, func() time.Time { return r.now })
	if err != nil {
		r.t.Fatal(err)
	}
	client, err := relay.New(r.fake.URL)
	if err != nil {
		r.t.Fatal(err)
	}
	client.RetryMin = 10 * time.Millisecond
	client.RetryMax = 50 * time.Millisecond
	if keepCursor {
		if err := client.UseCursorFile(filepath.Join(r.dir, "relay-cursor.json")); err != nil {
			r.t.Fatal(err)
		}
	}
	d.UseRelay(r.mac, client)
	return d, client
}

func (r *relayRig) cycle() {
	r.t.Helper()
	if _, err := r.d.Cycle(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

// raiseDown stops the fake service for two checks and returns the alert the
// relay received.
func (r *relayRig) raiseDown() relayAlert {
	r.t.Helper()
	r.src.Set(sysprobe.Snapshot{})
	r.cycle()
	r.cycle()
	alerts := r.alerts()
	if len(alerts) != 1 {
		r.t.Fatalf("relay alerts %+v", alerts)
	}
	return alerts[0]
}

type relayAlert struct {
	AlertID     string   `json:"alert_id"`
	ServiceID   string   `json:"service_id"`
	ServiceName string   `json:"service_name"`
	Kind        string   `json:"kind"`
	Message     string   `json:"message"`
	Actions     []string `json:"actions"`
}

type relayResult struct {
	AlertID string `json:"alert_id"`
	FixID   string `json:"fix_id"`
	Fixed   bool   `json:"fixed"`
	Message string `json:"message"`
}

func (r *relayRig) alerts() []relayAlert {
	r.t.Helper()
	var out []relayAlert
	for _, ev := range r.fake.Events(r.mac.MacID(), "alerts") {
		var a relayAlert
		if err := json.Unmarshal(ev.Body, &a); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func (r *relayRig) results() []relayResult {
	r.t.Helper()
	var out []relayResult
	for _, ev := range r.fake.Events(r.mac.MacID(), "results") {
		var res relayResult
		if err := json.Unmarshal(ev.Body, &res); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, res)
	}
	return out
}

func (r *relayRig) approve(signer ed25519.PrivateKey, macID, alertID, fixID string, expires time.Time) []byte {
	r.t.Helper()
	signed, err := security.Sign(signer, security.Approval{
		MacID:   macID,
		AlertID: alertID,
		FixID:   fixID,
		Nonce:   security.NewID(),
		Expires: expires,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	raw, err := security.MarshalApproval(signed)
	if err != nil {
		r.t.Fatal(err)
	}
	return raw
}

func (r *relayRig) count(kind, status string) int {
	r.t.Helper()
	n := 0
	for _, ev := range readEvents(r.t, r.book.Path()) {
		if ev.Kind == kind && (status == "" || ev.Status == status) {
			n++
		}
	}
	return n
}

func TestRelayApprovalRunsAllowlistedFix(t *testing.T) {
	r := newRelayRig(t)
	alert := r.raiseDown()
	if alert.ServiceID != "example-desktop-app" || alert.Kind != "down" || len(alert.Actions) != 1 || alert.Actions[0] != plugins.FixRestart {
		t.Fatalf("alert %+v", alert)
	}
	if alert.Message != "Example Desktop App has stopped. It is not running." {
		t.Fatalf("message %q", alert.Message)
	}

	r.fake.Store(r.mac.MacID(), "approvals", r.approve(r.phone, r.mac.MacID(), alert.AlertID, plugins.FixRestart, r.now.Add(5*time.Minute)))
	r.cycle()

	_, launches := r.ctrl.calls()
	if len(launches) != 1 || launches[0].path != exampleLauncher || len(launches[0].args) != 0 {
		t.Fatalf("launches %+v", launches)
	}
	results := r.results()
	if len(results) != 1 {
		t.Fatalf("results %+v", results)
	}
	got := results[0]
	if got.AlertID != alert.AlertID || got.FixID != plugins.FixRestart || !got.Fixed || !strings.HasPrefix(got.Message, "Fixed.") {
		t.Fatalf("result %+v", got)
	}
	if r.count("approval", "accepted") != 1 {
		t.Fatalf("log %s", mustRead(t, r.book.Path()))
	}
}

func TestRelayRefusesUnsafeApprovals(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	cases := []struct {
		name   string
		status security.Reason
		build  func(r *relayRig, alertID string) []byte
	}{
		{"bad signature", security.ReasonBadSignature, func(r *relayRig, alertID string) []byte {
			return forgeSignature(r.approve(r.phone, r.mac.MacID(), alertID, plugins.FixRestart, r.now.Add(5*time.Minute)))
		}},
		{"altered by relay", security.ReasonBadSignature, func(r *relayRig, alertID string) []byte {
			return alterFixID(r.approve(r.phone, r.mac.MacID(), alertID, plugins.FixRestart, r.now.Add(5*time.Minute)))
		}},
		{"unpaired phone", security.ReasonUnknownKey, func(r *relayRig, alertID string) []byte {
			_, other, err := ed25519.GenerateKey(nil)
			if err != nil {
				r.t.Fatal(err)
			}
			return r.approve(other, r.mac.MacID(), alertID, plugins.FixRestart, r.now.Add(5*time.Minute))
		}},
		{"expired", security.ReasonExpired, func(r *relayRig, alertID string) []byte {
			return r.approve(r.phone, r.mac.MacID(), alertID, plugins.FixRestart, r.now.Add(-time.Second))
		}},
		{"expiry too far ahead", security.ReasonWindow, func(r *relayRig, alertID string) []byte {
			return r.approve(r.phone, r.mac.MacID(), alertID, plugins.FixRestart, r.now.Add(time.Hour))
		}},
		{"other mac", security.ReasonMac, func(r *relayRig, alertID string) []byte {
			return r.approve(r.phone, security.NewID(), alertID, plugins.FixRestart, r.now.Add(5*time.Minute))
		}},
		{"unknown alert", security.ReasonUnknownAlert, func(r *relayRig, _ string) []byte {
			return r.approve(r.phone, r.mac.MacID(), security.NewID(), plugins.FixRestart, r.now.Add(5*time.Minute))
		}},
		{"fix not offered", security.ReasonWrongFix, func(r *relayRig, alertID string) []byte {
			return r.approve(r.phone, r.mac.MacID(), alertID, plugins.FixForceRestart, r.now.Add(5*time.Minute))
		}},
		{"command as fix id", security.ReasonWrongFix, func(r *relayRig, alertID string) []byte {
			return r.approve(r.phone, r.mac.MacID(), alertID, "restart; touch "+marker, r.now.Add(5*time.Minute))
		}},
		{"command field", security.ReasonMalformed, func(r *relayRig, alertID string) []byte {
			return addCommand(r.approve(r.phone, r.mac.MacID(), alertID, plugins.FixRestart, r.now.Add(5*time.Minute)))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelayRig(t)
			alert := r.raiseDown()
			r.fake.Store(r.mac.MacID(), "approvals", tc.build(r, alert.AlertID))
			r.cycle()
			signals, launches := r.ctrl.calls()
			if signals != 0 || len(launches) != 0 {
				t.Fatalf("refused approval ran a fix: signals %d launches %+v", signals, launches)
			}
			if got := r.results(); len(got) != 0 {
				t.Fatalf("results %+v", got)
			}
			if r.count("approval", string(tc.status)) != 1 || r.count("approval", "accepted") != 0 {
				t.Fatalf("log %s", mustRead(t, r.book.Path()))
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("a command from the relay created a file")
			}
		})
	}
}

func TestRelayReplayedApprovalRunsOnce(t *testing.T) {
	r := newRelayRig(t)
	alert := r.raiseDown()
	raw := r.approve(r.phone, r.mac.MacID(), alert.AlertID, plugins.FixRestart, r.now.Add(5*time.Minute))
	r.fake.Store(r.mac.MacID(), "approvals", raw)
	r.cycle()
	r.src.Set(sysprobe.Snapshot{})
	r.fake.Store(r.mac.MacID(), "approvals", raw)
	r.fake.Store(r.mac.MacID(), "approvals", raw)
	r.cycle()

	if _, launches := r.ctrl.calls(); len(launches) != 1 {
		t.Fatalf("launches %+v", launches)
	}
	if len(r.results()) != 1 {
		t.Fatalf("results %+v", r.results())
	}
	if r.count("approval", "accepted") != 1 || r.count("approval", string(security.ReasonReplay)) != 2 {
		t.Fatalf("log %s", mustRead(t, r.book.Path()))
	}
}

func TestRelayFixMustBeInPluginConfig(t *testing.T) {
	r := newRelayRig(t)
	alertID := security.NewID()
	if err := r.mac.RecordAlert(security.Raised{
		ID:        alertID,
		ServiceID: r.plug.ID,
		Kind:      "launchd",
		Actions:   []string{plugins.FixKickstart},
		At:        r.now,
	}); err != nil {
		t.Fatal(err)
	}
	r.fake.Store(r.mac.MacID(), "approvals", r.approve(r.phone, r.mac.MacID(), alertID, plugins.FixKickstart, r.now.Add(5*time.Minute)))
	r.cycle()

	if signals, launches := r.ctrl.calls(); signals != 0 || len(launches) != 0 {
		t.Fatalf("signals %d launches %+v", signals, launches)
	}
	results := r.results()
	if len(results) != 1 || results[0].Fixed || !strings.Contains(results[0].Message, "not approved") {
		t.Fatalf("results %+v", results)
	}
}

func TestRelayAlertIsResentAfterRelayError(t *testing.T) {
	r := newRelayRig(t)
	r.fake.Fail(http.MethodPost, "alerts", http.StatusServiceUnavailable, 2, "relay busy")
	r.src.Set(sysprobe.Snapshot{})
	r.cycle()
	r.cycle()
	if len(r.alerts()) != 0 || r.client.Pending() != 1 {
		t.Fatalf("alerts %+v pending %d", r.alerts(), r.client.Pending())
	}
	if r.count("relay", "") == 0 {
		t.Fatalf("log %s", mustRead(t, r.book.Path()))
	}
	r.cycle()
	alerts := r.alerts()
	if len(alerts) != 1 || alerts[0].Kind != "down" || r.client.Pending() != 0 {
		t.Fatalf("alerts %+v pending %d", alerts, r.client.Pending())
	}

	r.fake.Store(r.mac.MacID(), "approvals", r.approve(r.phone, r.mac.MacID(), alerts[0].AlertID, plugins.FixRestart, r.now.Add(5*time.Minute)))
	r.fake.Fail(http.MethodGet, "approvals", http.StatusInternalServerError, 1, "internal error")
	r.cycle()
	if _, launches := r.ctrl.calls(); len(launches) != 0 {
		t.Fatalf("launches %+v", launches)
	}
	r.fake.Fail(http.MethodGet, "approvals", http.StatusOK, 1, "<html>not a mailbox</html>")
	r.cycle()
	if _, launches := r.ctrl.calls(); len(launches) != 0 {
		t.Fatalf("launches %+v", launches)
	}
	r.cycle()
	if _, launches := r.ctrl.calls(); len(launches) != 1 {
		t.Fatalf("approval was not applied after the relay recovered: %+v", launches)
	}
	if len(r.results()) != 1 || !r.results()[0].Fixed {
		t.Fatalf("results %+v", r.results())
	}
}

func TestRelayUnreachableKeepsCheckingLocally(t *testing.T) {
	r := newRelayRig(t)
	r.client.HTTP.Timeout = 200 * time.Millisecond
	r.fake.Close()
	r.src.Set(sysprobe.Snapshot{})
	r.cycle()
	rows, err := r.d.Cycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].Alerts) != 1 || rows[0].Alerts[0].Kind != "down" {
		t.Fatalf("rows %+v", rows)
	}
	if r.client.Pending() != 1 || r.count("relay", "") == 0 {
		t.Fatalf("pending %d log %s", r.client.Pending(), mustRead(t, r.book.Path()))
	}
}

func TestRelayWatchAndPollApplyOnce(t *testing.T) {
	r := newRelayRig(t)
	alertID := security.NewID()
	if err := r.mac.RecordAlert(security.Raised{
		ID:        alertID,
		ServiceID: r.plug.ID,
		Kind:      "down",
		Actions:   []string{plugins.FixRestart},
		At:        r.now,
	}); err != nil {
		t.Fatal(err)
	}
	r.src.Set(sysprobe.Snapshot{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.d.Run(ctx, time.Hour, nil, nil) }()
	defer func() {
		cancel()
		<-done
	}()
	waitFor(t, func() bool { return r.fake.Listeners(r.mac.MacID()) == 1 })

	r.fake.Store(r.mac.MacID(), "approvals", r.approve(r.phone, r.mac.MacID(), alertID, plugins.FixRestart, r.now.Add(5*time.Minute)))
	waitFor(t, func() bool {
		_, launches := r.ctrl.calls()
		return len(launches) == 1
	})
	r.cycle()

	if _, launches := r.ctrl.calls(); len(launches) != 1 {
		t.Fatalf("launches %+v", launches)
	}
	if r.count("approval", string(security.ReasonReplay)) != 0 || r.count("approval", "accepted") != 1 {
		t.Fatalf("log %s", mustRead(t, r.book.Path()))
	}
	if len(r.results()) != 1 {
		t.Fatalf("results %+v", r.results())
	}
}

func TestRelayWatchReconnects(t *testing.T) {
	r := newRelayRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.d.Run(ctx, time.Hour, nil, nil) }()
	defer func() {
		cancel()
		<-done
	}()
	waitFor(t, func() bool { return r.fake.Listeners(r.mac.MacID()) == 1 })
	r.fake.DropSockets()
	waitFor(t, func() bool { return r.fake.Dials() >= 2 && r.fake.Listeners(r.mac.MacID()) == 1 })
}

func TestRelayCursorSurvivesRestart(t *testing.T) {
	r := newRelayRig(t)
	alert := r.raiseDown()
	r.fake.Store(r.mac.MacID(), "approvals", r.approve(r.phone, r.mac.MacID(), alert.AlertID, plugins.FixRestart, r.now.Add(5*time.Minute)))
	r.cycle()
	if _, launches := r.ctrl.calls(); len(launches) != 1 {
		t.Fatalf("launches %+v", launches)
	}

	r.d, r.client = r.doctor(true)
	r.cycle()
	if r.count("approval", string(security.ReasonReplay)) != 0 {
		t.Fatalf("restart re-read a handled approval: %s", mustRead(t, r.book.Path()))
	}

	r.d, r.client = r.doctor(false)
	r.cycle()
	if r.count("approval", string(security.ReasonReplay)) != 1 {
		t.Fatalf("without a cursor the nonce store must refuse the old approval: %s", mustRead(t, r.book.Path()))
	}
	if _, launches := r.ctrl.calls(); len(launches) != 1 {
		t.Fatalf("launches %+v", launches)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in 5s")
}
