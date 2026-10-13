package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZeroCool0388/daemon-doctor/internal/security"
	"github.com/coder/websocket"
)

type mcpRoundTrip func(*http.Request) (*http.Response, error)

func (f mcpRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeMCPClient(t *testing.T, check func(*http.Request)) *Client {
	t.Helper()
	c, err := New("https://relay.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP.Transport = mcpRoundTrip(func(r *http.Request) (*http.Response, error) {
		if check != nil {
			check(r)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"registered":true}`)), Request: r}, nil
	})
	return c
}

func TestMCPTokenAndRegistration(t *testing.T) {
	token, hash, err := NewMCPToken()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || len(hash) != 64 || hash != MCPTokenHash(token) {
		t.Fatal("invalid token or hash")
	}
	second, _, _ := NewMCPToken()
	if second == token {
		t.Fatal("token repeated")
	}
	c := fakeMCPClient(t, func(r *http.Request) {
		if r.Method != "PUT" || r.Header.Get("Authorization") != "Bearer link-secret" {
			t.Fatal("bad registration")
		}
		data, _ := io.ReadAll(r.Body)
		if strings.Contains(string(data), token) {
			t.Fatal("plaintext token sent")
		}
		if r.URL.Path == "/v1/macs/"+strings.Repeat("a", 32)+"/mcp-token" && string(data) != `{"token_hash":"`+hash+`"}` {
			t.Fatal("bad hash body")
		}
	})
	if err := c.RegisterMCPLink(context.Background(), strings.Repeat("a", 32), "link-secret", security.MCPLinkRegistration{SecretHash: MCPTokenHash("link-secret")}); err != nil {
		t.Fatal(err)
	}
	if err := c.RegisterMCPToken(context.Background(), strings.Repeat("a", 32), "link-secret", hash); err != nil {
		t.Fatal(err)
	}
}

type fakeLinkSocket struct {
	incoming chan []byte
	outgoing chan []byte
	closed   atomic.Bool
}

func newFakeLink() *fakeLinkSocket {
	return &fakeLinkSocket{incoming: make(chan []byte, 16), outgoing: make(chan []byte, 16)}
}
func (f *fakeLinkSocket) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case data := <-f.incoming:
		if data == nil {
			return 0, nil, io.EOF
		}
		return websocket.MessageText, data, nil
	}
}
func (f *fakeLinkSocket) Write(ctx context.Context, _ websocket.MessageType, data []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case f.outgoing <- data:
		return nil
	}
}
func (f *fakeLinkSocket) CloseNow() error { f.closed.Store(true); return nil }

func TestMCPLinkDispatchAndHeartbeat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sock := newFakeLink()
	l := &MCPLink{Client: fakeMCPClient(t, nil), MacID: strings.Repeat("b", 32), Secret: "private", heartbeat: 10 * time.Millisecond,
		Dispatch: func(_ context.Context, request json.RawMessage, _ http.Header) json.RawMessage {
			if string(request) != `{"jsonrpc":"2.0","id":7,"method":"ping"}` {
				t.Error("request changed")
			}
			return json.RawMessage(`{"jsonrpc":"2.0","id":7,"result":{}}`)
		},
		dial: func(_ context.Context, endpoint string, opts *websocket.DialOptions) (linkSocket, error) {
			if endpoint != "wss://relay.example.invalid/v1/macs/"+strings.Repeat("b", 32)+"/mcp-link" || opts.HTTPHeader.Get("Authorization") != "Bearer private" {
				t.Error("wrong link address/auth")
			}
			return sock, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- l.connect(ctx) }()
	sock.incoming <- []byte(`{"id":"relay-id","request":{"jsonrpc":"2.0","id":7,"method":"ping"}}`)
	select {
	case data := <-sock.outgoing:
		var reply struct {
			ID       string
			Response struct{ ID int }
		}
		if json.Unmarshal(data, &reply) != nil || reply.ID != "relay-id" || reply.Response.ID != 7 {
			t.Fatalf("bad reply %s", data)
		}
	case <-ctx.Done():
		t.Fatal("no reply")
	}
	select {
	case data := <-sock.outgoing:
		if string(data) != `{"type":"ping"}` {
			t.Fatal("missing heartbeat")
		}
	case <-ctx.Done():
		t.Fatal("no heartbeat")
	}
	sock.incoming <- []byte(`{"type":"pong"}`)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("link did not stop")
	}
	if !sock.closed.Load() {
		t.Fatal("socket left open")
	}
}

func TestMCPLinkReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var attempts atomic.Int32
	var registrations atomic.Int32
	c := fakeMCPClient(t, func(*http.Request) { registrations.Add(1) })
	l := &MCPLink{Client: c, MacID: strings.Repeat("c", 32), Secret: "private", retryMin: time.Millisecond, retryMax: 2 * time.Millisecond,
		dial: func(context.Context, string, *websocket.DialOptions) (linkSocket, error) {
			if attempts.Add(1) == 3 {
				cancel()
			}
			return nil, errors.New("offline")
		},
	}
	l.Run(ctx, nil)
	if attempts.Load() != 3 || registrations.Load() != 3 {
		t.Fatal("did not reconnect/register")
	}
}

func TestMCPLinkMissingHeartbeatStopsConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sock := newFakeLink()
	l := &MCPLink{Client: fakeMCPClient(t, nil), MacID: strings.Repeat("d", 32), Secret: "private", heartbeat: time.Millisecond,
		dial: func(context.Context, string, *websocket.DialOptions) (linkSocket, error) { return sock, nil },
	}
	if err := l.connect(ctx); err == nil {
		t.Fatal("silent link stayed alive")
	}
	if ctx.Err() != nil || !sock.closed.Load() {
		t.Fatal("heartbeat did not close promptly")
	}
}

func TestMCPLinkCancelsInFlightDispatchOnDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sock := newFakeLink()
	started := make(chan struct{})
	ended := make(chan struct{})
	l := &MCPLink{Client: fakeMCPClient(t, nil), MacID: strings.Repeat("e", 32), Secret: "private",
		dial: func(context.Context, string, *websocket.DialOptions) (linkSocket, error) { return sock, nil },
		Dispatch: func(ctx context.Context, _ json.RawMessage, _ http.Header) json.RawMessage {
			close(started)
			<-ctx.Done()
			close(ended)
			return nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- l.connect(ctx) }()
	sock.incoming <- []byte(`{"id":"one","request":{"jsonrpc":"2.0","id":1,"method":"ping"}}`)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("no dispatch")
	}
	sock.incoming <- nil
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("disconnect blocked")
	}
	select {
	case <-ended:
	default:
		t.Fatal("request was not cancelled")
	}
}

func TestMCPLinkDoesNotDispatchExpiredForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sock := newFakeLink()
	var calls atomic.Int32
	l := &MCPLink{Client: fakeMCPClient(t, nil), MacID: strings.Repeat("f", 32), Secret: "private",
		dial: func(context.Context, string, *websocket.DialOptions) (linkSocket, error) { return sock, nil },
		Dispatch: func(context.Context, json.RawMessage, http.Header) json.RawMessage {
			calls.Add(1)
			return json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{}}`)
		},
	}
	done := make(chan error, 1)
	go func() { done <- l.connect(ctx) }()
	sock.incoming <- []byte(`{"id":"expired","deadline_unix_ms":1,"request":{"jsonrpc":"2.0","id":1,"method":"ping"}}`)
	sock.incoming <- []byte(`{"id":"current","request":{"jsonrpc":"2.0","id":1,"method":"ping"}}`)
	select {
	case raw := <-sock.outgoing:
		if !strings.Contains(string(raw), "current") {
			t.Fatal("expired request dispatched")
		}
	case <-ctx.Done():
		t.Fatal("no current reply")
	}
	cancel()
	<-done
	if calls.Load() != 1 {
		t.Fatal("expired request dispatched")
	}
}

func TestMCPLinkFixCanFinishAfterDisconnectButStillHonorsDeadlineAndShutdown(t *testing.T) {
	for _, scenario := range []string{"finish", "deadline", "shutdown"} {
		t.Run(scenario, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			sock := newFakeLink()
			started := make(chan context.Context, 1)
			release := make(chan struct{})
			ended := make(chan error, 1)
			link := &MCPLink{Client: fakeMCPClient(t, nil), MacID: strings.Repeat("e", 32), Secret: "private",
				dial: func(context.Context, string, *websocket.DialOptions) (linkSocket, error) { return sock, nil },
				Dispatch: func(ctx context.Context, _ json.RawMessage, _ http.Header) json.RawMessage {
					started <- ctx
					select {
					case <-release:
						ended <- ctx.Err()
						return json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{"fixed":true}}`)
					case <-ctx.Done():
						ended <- ctx.Err()
						return nil
					}
				},
			}
			done := make(chan error, 1)
			go func() { done <- link.connect(parent) }()
			deadline := time.Now().Add(500 * time.Millisecond)
			if scenario == "deadline" {
				deadline = time.Now().Add(150 * time.Millisecond)
			}
			frame, _ := json.Marshal(map[string]any{"id": "fix", "deadline_unix_ms": deadline.UnixMilli(), "request": map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "run_fix", "arguments": map[string]any{"offer_id": strings.Repeat("a", 32)}}}})
			sock.incoming <- frame
			var callCtx context.Context
			select {
			case callCtx = <-started:
			case <-parent.Done():
				t.Fatal("fix did not start")
			}
			sock.incoming <- nil
			for !sock.closed.Load() && parent.Err() == nil {
				time.Sleep(time.Millisecond)
			}
			if scenario == "finish" {
				if callCtx.Err() != nil {
					t.Fatal("disconnect cancelled an authorized fix")
				}
				close(release)
			} else if scenario == "shutdown" {
				cancel()
			}
			select {
			case err := <-ended:
				if scenario == "finish" && err != nil || scenario == "deadline" && !errors.Is(err, context.DeadlineExceeded) || scenario == "shutdown" && !errors.Is(err, context.Canceled) {
					t.Fatalf("wrong fix context: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("fix did not finish or cancel")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("link shutdown hung")
			}
		})
	}
}

func TestMCPLinkForwardsClientProtocolHeaders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sock := newFakeLink()
	received := make(chan http.Header, 1)
	l := &MCPLink{Client: fakeMCPClient(t, nil), MacID: strings.Repeat("a", 32), Secret: "private",
		dial: func(context.Context, string, *websocket.DialOptions) (linkSocket, error) { return sock, nil },
		Dispatch: func(_ context.Context, _ json.RawMessage, headers http.Header) json.RawMessage {
			received <- headers
			return json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{}}`)
		},
	}
	done := make(chan error, 1)
	go func() { done <- l.connect(ctx) }()
	sock.incoming <- []byte(`{"id":"headers","protocol_version":"2026-07-28","mcp_headers":{"mcp-method":"tools/call","mcp-name":"list_services","authorization":"private"},"request":{"jsonrpc":"2.0","id":1,"method":"tools/call"}}`)
	select {
	case headers := <-received:
		if headers.Get("MCP-Protocol-Version") != "2026-07-28" || headers.Get("Mcp-Method") != "tools/call" || headers.Get("Mcp-Name") != "list_services" || headers.Get("Authorization") != "" {
			t.Fatal("protocol headers changed or credential forwarded")
		}
	case <-ctx.Done():
		t.Fatal("no dispatch")
	}
	cancel()
	<-done
}
