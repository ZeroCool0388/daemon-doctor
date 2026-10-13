package control_test

import (
	"context"
	"testing"

	"github.com/ZeroCool0388/daemon-doctor/internal/control"
	"github.com/ZeroCool0388/daemon-doctor/internal/demo"
)

func TestFixResultValidatesReadRequestAndDoesNotExecute(t *testing.T) {
	for _, bad := range []control.Request{{Method: "fix_result"}, {Method: "fix_result", OfferID: "id", Service: "other"}, {Method: "fix_result", OfferID: "id", Limit: 1}, {Method: "fix_result", OfferID: "id", ID: "other"}} {
		if err := bad.Validate(); err == nil {
			t.Fatal("invalid result request accepted", bad)
		}
	}
	backend, err := demo.NewMCP()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	value, err := backend.Call(ctx, control.Request{Method: "offers"})
	if err != nil {
		t.Fatal(err)
	}
	// Normalize the typed offer list through the public sanitizer.
	data, err := control.Sanitize(value)
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.Call(ctx, control.Request{Method: "fix_result", OfferID: "unknown"})
	if err != nil || result.(map[string]any)["status"] != "unknown" {
		t.Fatalf("unknown read: %+v %v", result, err)
	}
	after, err := backend.Call(ctx, control.Request{Method: "offers"})
	if err != nil {
		t.Fatal(err)
	}
	afterData, err := control.Sanitize(after)
	if err != nil || string(afterData) != string(data) {
		t.Fatalf("result read changed offers: %s %s %v", data, afterData, err)
	}
}
