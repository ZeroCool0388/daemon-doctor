package demo

import (
	"context"
	"sync"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/control"
	"github.com/ZeroCool0388/daemon-doctor/internal/doctor"
	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
	"github.com/ZeroCool0388/daemon-doctor/internal/offers"
	"github.com/ZeroCool0388/daemon-doctor/internal/sysprobe"
)

// MCP is an interactive version of the same fictional services and incidents.
// Reads advance its fake timeline; fixes act only on the in-memory world.
type MCP struct {
	mu     sync.Mutex
	local  *control.Local
	clock  *clock
	world  *world
	src    *sysprobe.MemSource
	events []logbook.Event
	step   int
}

func NewMCP() (*MCP, error) {
	c := &clock{t: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)}
	w := &world{appUp: true, appOut: false, syncUp: true, mailUp: true, bridgeUp: true, networkUp: true}
	src := &sysprobe.MemSource{}
	d, err := doctor.New(scriptPlugins(), src, &stage{src: src, world: w}, nil, nil, c.now)
	if err != nil {
		return nil, err
	}
	store, err := offers.Open("")
	if err != nil {
		return nil, err
	}
	d.UseOffers(store)
	b := &MCP{local: &control.Local{Doctor: d, AllowFixes: true}, clock: c, world: w, src: src, events: []logbook.Event{}}
	// Begin at the first stuck incident, ready to demonstrate a one-use fix.
	for range 3 {
		if err = b.advance(); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (b *MCP) advance() error {
	b.clock.advance(time.Minute)
	b.src.Set(b.world.snapshot())
	rows, err := b.local.Doctor.Cycle(context.Background())
	if err != nil {
		return err
	}
	for _, row := range rows {
		for _, a := range row.Alerts {
			offered := a.OfferFix
			b.events = append(b.events, logbook.Event{Time: a.At, Kind: "alert", ServiceID: a.ServiceID, ServiceName: a.ServiceName, AlertID: a.ID, AlertKind: a.Kind, Message: a.Message, OfferFix: &offered})
		}
	}
	if len(b.events) > 50 {
		b.events = b.events[len(b.events)-50:]
	}
	return nil
}

func (b *MCP) Call(ctx context.Context, r control.Request) (any, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if r.Method == "status" {
		// The same replay scenes: stuck app, network hold/recovery, CPU hog,
		// then three bridge incidents. Only list_services advances scenes.
		b.step++
		switch b.step {
		case 2:
			b.world.networkUp = false
			b.world.mailUp = false
		case 3:
			b.world.networkUp = true
		case 5:
			b.world.hog = true
		case 6:
			b.clock.advance(5 * time.Minute)
		case 7, 9, 11:
			b.world.bridgeUp = false
		case 8, 10:
			b.world.bridgeUp = true
		}
		if err := b.advance(); err != nil {
			return nil, err
		}
		if b.step == 7 || b.step == 9 || b.step == 11 {
			if err := b.advance(); err != nil {
				return nil, err
			}
		}
	}
	if r.Method == "events" {
		limit := r.Limit
		if limit == 0 {
			limit = 20
		}
		if limit > 50 {
			limit = 50
		}
		rows := []logbook.Event{}
		for i := len(b.events) - 1; i >= 0 && len(rows) < limit; i-- {
			rows = append(rows, b.events[i])
		}
		return map[string]any{"events": rows}, nil
	}
	value, err := b.local.Call(ctx, r)
	if r.Method == "run_fix" {
		msg := ""
		fixed := false
		if result, ok := value.(map[string]any); ok {
			msg, _ = result["message"].(string)
			fixed, _ = result["fixed"].(bool)
		}
		if err != nil {
			msg = err.Error()
		}
		b.events = append(b.events, logbook.Event{Time: b.clock.now(), Kind: "fix", Source: "mcp", Fixed: &fixed, Message: msg})
	}
	return value, err
}
