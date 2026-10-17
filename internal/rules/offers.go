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
			// A short pressure dip keeps the fix offer. A different largest
			// process pauses it. The incident itself stays until the recovery
			// grace expires.
			w = e.mac.mem.hogWatch
		}
		return w.active && w.name == a.Process && w.watched == (a.ServiceID != UnwatchedID)
	default:
		st := e.svc[a.ServiceID]
		return st != nil && st.active == a.Kind
	}
}

// FixEligible checks whether an active alert can currently offer its fix.
// A memory offer remains available through a dip shorter than
// memoryOfferDipTolerance. Temporary ineligibility must not withdraw the incident.
func (e *Engine) FixEligible(a Alert) bool {
	if !e.AlertActive(a) {
		return false
	}
	return a.Kind != KindMemoryHog || e.mac.mem.fixEligible
}

// MemoryEligibilityReason explains why a memory fix cannot be applied for a.
// It is empty when the fix is eligible. Callers record the text on refusal.
func (e *Engine) MemoryEligibilityReason(a Alert) string {
	if a.Kind != KindMemoryHog || e.FixEligible(a) {
		return ""
	}
	if e.mac == nil {
		return "memory pressure has not been sampled"
	}
	w := e.mac.mem
	if w.block != "" {
		return w.block
	}
	if w.started && w.name != "" && (w.name != a.Process || w.serviceID != a.ServiceID) {
		return "a different process is now the largest memory user"
	}
	if !w.active {
		return "memory pressure has returned to normal"
	}
	return "the alerted process is no longer the largest memory user"
}

// ResumeMemoryAlert restores a verified saved incident in a fresh engine only
// when its latest reading is above the configured level with the same top
// process and watched-service attribution. It does not create another alert.
func (e *Engine) ResumeMemoryAlert(a Alert) bool {
	if a.Kind != KindMemoryHog || e.mac == nil {
		return false
	}
	w := &e.mac.mem
	if w.active || !w.started || !w.fixEligible || w.name != a.Process || w.serviceID != a.ServiceID {
		return false
	}
	w.active = true
	e.mac.syncStop()
	return true
}
