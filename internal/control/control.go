// Package control is a bounded, private Unix-socket protocol. No command text
// or arbitrary arguments are accepted by this surface.
package control

import (
	"context"
	"fmt"
	"github.com/ZeroCool0388/daemon-doctor/internal/doctor"
	"github.com/ZeroCool0388/daemon-doctor/internal/logbook"
)

type Request struct {
	Method  string `json:"method"`
	ID      string `json:"id,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	OfferID string `json:"offer_id,omitempty"`
	Service string `json:"service,omitempty"`
}

type Backend interface {
	Call(context.Context, Request) (any, error)
}

type Local struct {
	Doctor     *doctor.Doctor
	AllowFixes bool
}

func (r Request) Validate() error {
	switch r.Method {
	case "status", "offers":
		if r.ID != "" || r.Limit != 0 || r.OfferID != "" || r.Service != "" {
			return fmt.Errorf("unexpected parameters")
		}
	case "service":
		if r.ID == "" || r.Limit != 0 || r.OfferID != "" || r.Service != "" {
			return fmt.Errorf("service requires only id")
		}
	case "events":
		if r.ID != "" || r.Limit < 0 || r.OfferID != "" || r.Service != "" {
			return fmt.Errorf("events accepts only a nonnegative limit")
		}
	case "run_fix":
		if r.OfferID == "" || r.ID != "" || r.Limit != 0 {
			return fmt.Errorf("run_fix requires offer_id and optional service")
		}
	default:
		return fmt.Errorf("unknown control method %q", r.Method)
	}
	return nil
}

func (b *Local) Call(ctx context.Context, r Request) (any, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	switch r.Method {
	case "status", "service":
		rows, at, err := b.Doctor.Snapshot()
		if err != nil {
			return nil, err
		}
		if r.Method == "service" {
			for _, row := range rows {
				if row.ID == r.ID {
					return map[string]any{"service": row, "sampled_at": at}, nil
				}
			}
			return nil, fmt.Errorf("unknown service %q", r.ID)
		}
		return map[string]any{"services": rows, "sampled_at": at}, nil
	case "events":
		events, err := b.Doctor.RecentEvents(r.Limit)
		return map[string]any{"events": events}, err
	case "offers":
		items, err := b.Doctor.OfferedFixes()
		return map[string]any{"offers": items, "fixes_enabled": b.AllowFixes}, err
	case "run_fix":
		if !b.AllowFixes {
			b.Doctor.RecordMCPRefusal(r.OfferID, "MCP fixes are disabled in the daemon configuration")
			return nil, fmt.Errorf("MCP fixes are disabled in the daemon configuration")
		}
		res, err := b.Doctor.ApplyOffer(ctx, r.OfferID, r.Service, false)
		return map[string]any{"fixed": err == nil && res.Fixed, "message": logbook.Blank(res.Message), "detail": logbook.Blank(res.Detail)}, err
	}
	return nil, fmt.Errorf("unknown method")
}
