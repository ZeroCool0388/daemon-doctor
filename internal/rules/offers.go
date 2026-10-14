package rules

// AlertActive checks live rule state without advancing streaks or creating alerts.
func (e *Engine) AlertActive(a Alert) bool {
	if !a.OfferFix {
		return false
	}
	if st := e.svc[a.ServiceID]; st != nil && len(prune(st.incidents, e.now().Add(-keepsWindow))) >= keepsLimit {
		return false
	}
	switch a.Kind {
	case KindCPUHog, KindMemoryHog:
		if e.mac == nil {
			return false
		}
		w := e.mac.cpu
		if a.Kind == KindMemoryHog {
			// A temporary dip or attribution change pauses the fix, but the
			// memory incident remains active until its recovery grace expires.
			w = e.mac.mem.hogWatch
		}
		return w.active && w.name == a.Process && w.watched == (a.ServiceID != UnwatchedID)
	default:
		st := e.svc[a.ServiceID]
		return st != nil && st.active == a.Kind
	}
}

// FixEligible checks whether an active alert can currently offer its fix.
// Temporary memory ineligibility must not withdraw the incident itself.
func (e *Engine) FixEligible(a Alert) bool {
	if !e.AlertActive(a) {
		return false
	}
	return a.Kind != KindMemoryHog || e.mac.mem.fixEligible
}
