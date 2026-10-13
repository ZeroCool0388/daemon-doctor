package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func privateTopic(t *testing.T) string {
	t.Helper()
	topic, err := GenerateTopic()
	if err != nil {
		t.Fatal(err)
	}
	return topic
}

func TestNtfyDefaultsDisabledAndRandomTopic(t *testing.T) {
	cfg, err := (Config{}).Clean()
	if err != nil || cfg.Server != DefaultServer || cfg.Enabled {
		t.Fatal("invalid ntfy defaults")
	}
	n, err := New(Config{})
	if err != nil || n != nil {
		t.Fatal("disabled notifications created a sender")
	}
	first, second := privateTopic(t), privateTopic(t)
	if len(first) != 43 || !topicPattern.MatchString(first) || first == second {
		t.Fatal("invalid generated topic")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", Config{Topic: first}, Config{Topic: first}), first) {
		t.Fatal("config diagnostics disclosed the topic")
	}
}

func TestNtfyPublishesPlainEnglishStateAndHidesErrors(t *testing.T) {
	topic := privateTopic(t)
	n, err := New(Config{Enabled: true, Topic: topic})
	if err != nil {
		t.Fatal(err)
	}
	var message string
	n.HTTP.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != "POST" || req.URL.Path != "/"+topic || req.Header.Get("Title") != "Daemon Doctor" || req.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Error("incorrect ntfy request")
		}
		bytes, _ := io.ReadAll(req.Body)
		message = string(bytes)
		if deadline, ok := req.Context().Deadline(); !ok || time.Until(deadline) > SendTimeout {
			t.Error("unbounded delivery")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Request: req}, nil
	})
	for _, tc := range []struct{ state, want string }{{"down", "Example Sync is down. It is not running."}, {"stuck", "Example Sync looks stuck. It is running but not responding as expected."}, {"ok", "Example Sync has recovered and looks healthy."}} {
		if err := n.Send(context.Background(), Event{ServiceName: "Example Sync", State: tc.state}); err != nil || message != tc.want {
			t.Fatal("incorrect state notification")
		}
	}
	n.HTTP.Transport = transportFunc(func(req *http.Request) (*http.Response, error) { return nil, errors.New(req.URL.String()) })
	err = n.Send(context.Background(), Event{ServiceName: "Example", State: "down"})
	if err == nil || strings.Contains(err.Error(), topic) {
		t.Fatal("transport error disclosed topic")
	}
	n.HTTP.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(topic)), Request: req}, nil
	})
	err = n.Send(context.Background(), Event{ServiceName: "Example", State: "down"})
	if err == nil || strings.Contains(err.Error(), topic) {
		t.Fatal("response error disclosed topic")
	}
}

func TestNtfyRejectsRedirectAndHonoursCancellation(t *testing.T) {
	topic := privateTopic(t)
	n, _ := New(Config{Enabled: true, Topic: topic})
	calls := 0
	n.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	n.HTTP.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://other.example.invalid/" + topic}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	if n.Send(context.Background(), Event{State: "down"}) == nil || calls != 1 {
		t.Fatal("redirect forwarded a private topic")
	}
	started := make(chan struct{})
	n.HTTP.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Send(ctx, Event{State: "down"}) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("delivery did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || strings.Contains(err.Error(), topic) {
			t.Error("invalid cancellation error")
		}
	case <-time.After(time.Second):
		t.Fatal("delivery did not stop")
	}
}
