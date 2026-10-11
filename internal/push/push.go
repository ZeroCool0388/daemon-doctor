// Package push is the phone notification hook.
// The stub does not call a push service and it holds no keys.
package push

import "context"

// Hook delivers an alert id to a paired phone.
type Hook interface {
	Deliver(ctx context.Context, macID, alertID, message string) error
}

// Stub is the FCM hook with no credentials and no network call.
type Stub struct{}

// Deliver does nothing.
func (Stub) Deliver(context.Context, string, string, string) error { return nil }
