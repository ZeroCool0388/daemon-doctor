// Package relaytest is an in-process copy of the mailbox worker in relay/src
// for tests. It keeps the worker's routes, status codes, body limit, shared
// per-Mac event ids, and WebSocket broadcast. It never runs a stored body.
package relaytest

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// MaxBody is the worker's request body limit in bytes.
const MaxBody = 4096

// Boxes are the mailbox kinds the worker stores.
var Boxes = []string{"pairing", "alerts", "approvals", "results"}

var macID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Event is one stored mailbox record, as the worker returns it.
type Event struct {
	ID   int64           `json:"id"`
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

// Relay is a fake mailbox worker behind an httptest server.
type Relay struct {
	*httptest.Server

	mu      sync.Mutex
	boxes   map[string]*mailbox
	faults  []fault
	sockets map[*websocket.Conn]string
	dials   int
}

type mailbox struct {
	next   int64
	events []Event
}

type fault struct {
	method string
	box    string
	status int
	body   string
	left   int
}

// New starts a fake relay. Close it when the test ends.
func New() *Relay {
	r := &Relay{boxes: map[string]*mailbox{}, sockets: map[*websocket.Conn]string{}}
	r.Server = httptest.NewServer(http.HandlerFunc(r.serve))
	return r
}

// Close drops open sockets and stops the server.
func (r *Relay) Close() {
	r.DropSockets()
	r.Server.Close()
}

// Fail makes the next n requests with this method to this box return status
// with body. An empty method or box matches any.
func (r *Relay) Fail(method, box string, status, n int, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.faults = append(r.faults, fault{method: method, box: box, status: status, body: body, left: n})
}

// Store saves body as if a phone posted it, and broadcasts it.
func (r *Relay) Store(mac, box string, body []byte) int64 {
	r.mu.Lock()
	ev := r.storeLocked(mac, box, body)
	r.mu.Unlock()
	r.broadcast(mac, ev)
	return ev.ID
}

// Events returns the stored records of one box in id order.
func (r *Relay) Events(mac, box string) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Event
	if b, ok := r.boxes[mac]; ok {
		for _, ev := range b.events {
			if ev.Kind == box {
				out = append(out, ev)
			}
		}
	}
	return out
}

// Reset drops every stored event, like a fresh Durable Object.
func (r *Relay) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.boxes = map[string]*mailbox{}
}

// Dials is how many WebSocket connections were accepted.
func (r *Relay) Dials() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dials
}

// Listeners is how many WebSocket connections are open for mac.
func (r *Relay) Listeners(mac string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, m := range r.sockets {
		if m == mac {
			n++
		}
	}
	return n
}

// DropSockets closes every open WebSocket.
func (r *Relay) DropSockets() {
	r.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(r.sockets))
	for c := range r.sockets {
		conns = append(conns, c)
	}
	r.sockets = map[*websocket.Conn]string{}
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close(websocket.StatusGoingAway, "")
	}
}

func (r *Relay) serve(w http.ResponseWriter, req *http.Request) {
	parts := strings.FieldsFunc(req.URL.Path, func(c rune) bool { return c == '/' })
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "macs" {
		text(w, "not found", http.StatusNotFound)
		return
	}
	if !macID.MatchString(parts[2]) {
		text(w, "bad mac id", http.StatusBadRequest)
		return
	}
	mac, box := parts[2], parts[3]
	if box != "ws" && !isBox(box) {
		text(w, "not found", http.StatusNotFound)
		return
	}
	if f, ok := r.takeFault(req.Method, box); ok {
		text(w, f.body, f.status)
		return
	}
	switch {
	case box == "ws":
		r.socket(w, req, mac)
	case req.Method == http.MethodGet:
		r.list(w, req, mac, box)
	case req.Method == http.MethodPost:
		r.store(w, req, mac, box)
	default:
		text(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *Relay) takeFault(method, box string) (fault, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.faults {
		f := &r.faults[i]
		if f.left <= 0 || (f.method != "" && f.method != method) || (f.box != "" && f.box != box) {
			continue
		}
		f.left--
		return *f, true
	}
	return fault{}, false
}

func (r *Relay) store(w http.ResponseWriter, req *http.Request, mac, box string) {
	if req.ContentLength > MaxBody {
		text(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, MaxBody+1))
	if err != nil {
		text(w, "json object required", http.StatusBadRequest)
		return
	}
	if len(raw) > MaxBody {
		text(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		text(w, "json object required", http.StatusBadRequest)
		return
	}
	compact, err := json.Marshal(obj)
	if err != nil {
		text(w, "json object required", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	ev := r.storeLocked(mac, box, compact)
	r.mu.Unlock()
	r.broadcast(mac, ev)
	if box == "alerts" {
		writeJSON(w, map[string]any{"stored": true, "push": "stub", "id": ev.ID})
		return
	}
	writeJSON(w, map[string]any{"stored": true, "id": ev.ID})
}

func (r *Relay) storeLocked(mac, box string, body []byte) Event {
	b, ok := r.boxes[mac]
	if !ok {
		b = &mailbox{next: 1}
		r.boxes[mac] = b
	}
	ev := Event{ID: b.next, Kind: box, Body: append(json.RawMessage(nil), body...)}
	b.next++
	b.events = append(b.events, ev)
	return ev
}

func (r *Relay) list(w http.ResponseWriter, req *http.Request, mac, box string) {
	after := afterParam(req.URL.Query().Get("after"))
	r.mu.Lock()
	events := []Event{}
	if b, ok := r.boxes[mac]; ok {
		for _, ev := range b.events {
			if ev.Kind == box && ev.ID > after {
				events = append(events, ev)
			}
		}
	}
	r.mu.Unlock()
	writeJSON(w, map[string]any{"events": events})
}

// afterParam matches Math.max(0, Math.floor(Number(raw) || 0)).
func afterParam(raw string) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(n) || n <= 0 {
		return 0
	}
	if math.IsInf(n, 1) || n > math.MaxInt64/2 {
		return math.MaxInt64 / 2
	}
	return int64(math.Floor(n))
}

func (r *Relay) socket(w http.ResponseWriter, req *http.Request, mac string) {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		text(w, "upgrade required", http.StatusUpgradeRequired)
		return
	}
	conn, err := websocket.Accept(w, req, nil)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.sockets[conn] = mac
	r.dials++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.sockets, conn)
		r.mu.Unlock()
	}()
	ctx := conn.CloseRead(context.Background())
	<-ctx.Done()
}

func (r *Relay) broadcast(mac string, ev Event) {
	frame, err := json.Marshal(ev)
	if err != nil {
		return
	}
	r.mu.Lock()
	var conns []*websocket.Conn
	for c, m := range r.sockets {
		if m == mac {
			conns = append(conns, c)
		}
	}
	r.mu.Unlock()
	for _, c := range conns {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := c.Write(ctx, websocket.MessageText, frame); err != nil {
			r.mu.Lock()
			delete(r.sockets, c)
			r.mu.Unlock()
		}
		cancel()
	}
}

func isBox(box string) bool {
	for _, b := range Boxes {
		if b == box {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func text(w http.ResponseWriter, body string, status int) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
