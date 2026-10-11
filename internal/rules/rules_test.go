package rules

import (
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/checks"
	"github.com/ZeroCool0388/daemon-doctor/internal/plugins"
)

func plugin() plugins.Plugin {
	return plugins.Plugin{
		ID:   "example-desktop-app",
		Name: "Example Desktop App",
		Messages: plugins.Messages{
			Down:           "Example Desktop App has stopped. It is not running.",
			Stuck:          "Example Desktop App is open but has no established outbound connection on port 443, so it looks stuck.",
			KeepsHappening: "Example Desktop App has failed 3 times in the last hour. Automatic fixes are paused.",
		},
		Fixes: map[string]plugins.Fix{
			plugins.FixRestart:      {Kind: plugins.FixRestart},
			plugins.FixForceRestart: {Kind: plugins.FixForceRestart},
		},
	}
}

func notRunning() []checks.Outcome {
	return []checks.Outcome{{
		Type:       plugins.CheckProcessRunning,
		NotRunning: true,
		Failed:     true,
		Detail:     "process example-desktop-app is not running",
	}}
}

func stuck() []checks.Outcome {
	return []checks.Outcome{
		{Type: plugins.CheckProcessRunning, Healthy: true},
		{Type: plugins.CheckOutboundTCP, Failed: true, Stuck: true},
	}
}

func healthy() []checks.Outcome {
	return []checks.Outcome{
		{Type: plugins.CheckProcessRunning, Healthy: true},
		{Type: plugins.CheckOutboundTCP, Healthy: true},
	}
}

func TestDownNeedsTwoChecksAndDoesNotRepeat(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	eng := NewEngine(func() time.Time { return now })
	p := plugin()

	first := eng.Decide(p, notRunning())
	if first.Status != StatusPending || len(first.Alerts) != 0 {
		t.Fatalf("first miss: %+v", first)
	}
	second := eng.Decide(p, notRunning())
	if second.Status != StatusDown || len(second.Alerts) != 1 {
		t.Fatalf("second miss: %+v", second)
	}
	alert := second.Alerts[0]
	if alert.Kind != KindDown || !alert.OfferFix || alert.Action != plugins.FixRestart {
		t.Fatalf("alert: %+v", alert)
	}
	if alert.Message != p.Messages.Down {
		t.Fatalf("message: %q", alert.Message)
	}
	third := eng.Decide(p, notRunning())
	if third.Status != StatusDown || len(third.Alerts) != 0 {
		t.Fatalf("repeat down should be quiet: %+v", third)
	}

	if got := eng.Decide(p, healthy()); got.Status != StatusOK || len(got.Alerts) != 0 {
		t.Fatalf("recovery: %+v", got)
	}
	eng.Decide(p, notRunning())
	again := eng.Decide(p, notRunning())
	if len(again.Alerts) != 1 || again.Alerts[0].Kind != KindDown {
		t.Fatalf("a new outage should alert: %+v", again)
	}
}

func TestStuckWhileProcessIsUp(t *testing.T) {
	eng := NewEngine(nil)
	p := plugin()
	got := eng.Decide(p, stuck())
	if got.Status != StatusStuck || len(got.Alerts) != 1 {
		t.Fatalf("verdict: %+v", got)
	}
	alert := got.Alerts[0]
	if alert.Kind != KindStuck || alert.Action != plugins.FixForceRestart || !alert.OfferFix {
		t.Fatalf("alert: %+v", alert)
	}
	if alert.Message != p.Messages.Stuck {
		t.Fatalf("message: %q", alert.Message)
	}
	if again := eng.Decide(p, stuck()); len(again.Alerts) != 0 {
		t.Fatalf("repeat stuck should be quiet: %+v", again)
	}
}

func TestNoFixOfferedWhenActionIsNotApproved(t *testing.T) {
	eng := NewEngine(nil)
	p := plugin()
	delete(p.Fixes, plugins.FixRestart)
	got := eng.Decide(p, notRunning())
	got = eng.Decide(p, notRunning())
	if len(got.Alerts) != 1 || got.Alerts[0].OfferFix {
		t.Fatalf("unapproved restart should not be offered: %+v", got.Alerts)
	}
}

func TestKeepsHappeningPausesFixes(t *testing.T) {
	start := time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC)
	now := start
	eng := NewEngine(func() time.Time { return now })
	p := plugin()

	var third Verdict
	for i := 0; i < 3; i++ {
		now = start.Add(time.Duration(i) * 10 * time.Minute)
		eng.Decide(p, notRunning())
		third = eng.Decide(p, notRunning())
		if i < 2 {
			eng.Decide(p, healthy())
		}
	}
	if len(third.Alerts) != 1 || third.Alerts[0].Kind != KindKeepsHappening || third.Alerts[0].OfferFix {
		t.Fatalf("third failure: %+v", third.Alerts)
	}
	if third.Alerts[0].Message != p.Messages.KeepsHappening {
		t.Fatalf("message: %q", third.Alerts[0].Message)
	}
	if third.Status != StatusDown {
		t.Fatalf("status: %s", third.Status)
	}

	eng.Decide(p, healthy())
	now = start.Add(30 * time.Minute)
	eng.Decide(p, notRunning())
	fourth := eng.Decide(p, notRunning())
	if len(fourth.Alerts) != 1 || fourth.Alerts[0].Kind != KindDown || fourth.Alerts[0].OfferFix {
		t.Fatalf("later failure should alert without a fix: %+v", fourth.Alerts)
	}

	eng.Decide(p, healthy())
	now = start.Add(3 * time.Hour)
	eng.Decide(p, notRunning())
	later := eng.Decide(p, notRunning())
	if len(later.Alerts) != 1 || !later.Alerts[0].OfferFix || later.Alerts[0].Kind != KindDown {
		t.Fatalf("old failures should age out: %+v", later.Alerts)
	}
}

func TestFailureJustOutsideTheHourDoesNotCount(t *testing.T) {
	start := time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC)
	now := start
	eng := NewEngine(func() time.Time { return now })
	p := plugin()

	eng.Decide(p, notRunning())
	eng.Decide(p, notRunning())
	eng.Decide(p, healthy())

	now = start.Add(10 * time.Minute)
	eng.Decide(p, notRunning())
	eng.Decide(p, notRunning())
	eng.Decide(p, healthy())

	now = start.Add(time.Hour + time.Nanosecond)
	eng.Decide(p, notRunning())
	got := eng.Decide(p, notRunning())
	if len(got.Alerts) != 1 || got.Alerts[0].Kind != KindDown || !got.Alerts[0].OfferFix {
		t.Fatalf("the first failure is outside the hour: %+v", got.Alerts)
	}
}
