package relaytest

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const mac = "0123456789abcdef0123456789abcdef"

func TestMatchesWorkerSource(t *testing.T) {
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "relay", "src", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	index, mailbox := read("index.ts"), read("mailbox.ts")
	for _, box := range Boxes {
		if !strings.Contains(index, `box !== "`+box+`"`) || !strings.Contains(mailbox, `"`+box+`"`) {
			t.Fatalf("worker does not route %s", box)
		}
	}
	if !strings.Contains(mailbox, "MAX_BODY = "+strconv.Itoa(MaxBody)) {
		t.Fatal("worker body limit changed")
	}
	if !strings.Contains(index, "/^[a-f0-9]{32}$/") {
		t.Fatal("worker mac id pattern changed")
	}
}

func TestRoutesAndStatusCodes(t *testing.T) {
	r := New()
	defer r.Close()
	cases := []struct {
		method, path, body string
		status             int
	}{
		{http.MethodPost, "/v1/exec", `{"command":"restart"}`, http.StatusNotFound},
		{http.MethodPost, "/v1/macs/not-a-mac/alerts", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/macs/" + mac + "/commands", `{}`, http.StatusNotFound},
		{http.MethodPost, "/v1/macs/" + mac + "/alerts", `[1]`, http.StatusBadRequest},
		{http.MethodPost, "/v1/macs/" + mac + "/alerts", `{"pad":"` + strings.Repeat("a", MaxBody) + `"}`, http.StatusRequestEntityTooLarge},
		{http.MethodPut, "/v1/macs/" + mac + "/alerts", `{}`, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/macs/" + mac + "/ws", ``, http.StatusUpgradeRequired},
	}
	for _, tc := range cases {
		req, err := http.NewRequest(tc.method, r.URL+tc.path, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("%s %s: %d, want %d", tc.method, tc.path, res.StatusCode, tc.status)
		}
	}
}

func TestStoreAndList(t *testing.T) {
	r := New()
	defer r.Close()
	post := func(box, body string) map[string]any {
		res, err := http.Post(r.URL+"/v1/macs/"+mac+"/"+box, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	alert := post("alerts", `{"alert_id":"x"}`)
	if alert["stored"] != true || alert["push"] != "stub" || alert["id"] != float64(1) {
		t.Fatalf("alert reply %v", alert)
	}
	approval := post("approvals", `{"fix_id":"restart"}`)
	if _, ok := approval["push"]; ok || approval["id"] != float64(2) {
		t.Fatalf("approval reply %v", approval)
	}
	for _, tc := range []struct {
		after string
		n     int
	}{{"", 1}, {"0", 1}, {"1.9", 1}, {"-5", 1}, {"abc", 1}, {"2", 0}} {
		res, err := http.Get(r.URL + "/v1/macs/" + mac + "/approvals?after=" + tc.after)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		var page struct {
			Events []Event `json:"events"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Events) != tc.n {
			t.Fatalf("after=%q: %s", tc.after, body)
		}
	}
}
