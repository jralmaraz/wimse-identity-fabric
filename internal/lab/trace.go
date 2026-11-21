// Package lab contains the building blocks of the local multi-cloud lab
// (deploy/local-multicloud): trust bundles keyed by trust domain, a WIMSE
// request verifier and client agent for net/http services, and a
// fire-and-forget event emitter that feeds the transaction observer UI.
//
// The lab composes the library packages (pkg/wit, pkg/wpt, pkg/txntoken,
// pkg/keys) – it does not re-implement token formats.
package lab

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Check is one verification step shown in the observer UI.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Event is one transaction (an arrow in the observer's sequence view).
//
// DEMO ONLY: events carry full tokens so the UI can decode them. Never ship
// raw credentials to a real log or tracing backend.
type Event struct {
	ID      string            `json:"id"`
	TS      float64           `json:"ts"`
	TraceID string            `json:"trace_id"`
	Kind    string            `json:"kind"` // attest | wimse-call | txn-token | token-exchange | cloud | attack | info
	Src     string            `json:"src"`
	Dst     string            `json:"dst"`
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Status  int               `json:"status,omitempty"`
	OK      bool              `json:"ok"`
	Summary string            `json:"summary"`
	Tokens  map[string]string `json:"tokens,omitempty"`
	Checks  []Check           `json:"checks,omitempty"`
	Extra   map[string]any    `json:"extra,omitempty"`
}

var (
	observerURL = strings.TrimRight(os.Getenv("OBSERVER_URL"), "/")
	traceClient = &http.Client{Timeout: 2 * time.Second}
	traceQueue  = make(chan Event, 256)
)

func init() {
	if observerURL != "" {
		go func() {
			for e := range traceQueue {
				body, _ := json.Marshal(e)
				resp, err := traceClient.Post(observerURL+"/events", "application/json", bytes.NewReader(body))
				if err == nil {
					resp.Body.Close()
				}
			}
		}()
	}
}

// Emit logs the event and ships it to the observer (if OBSERVER_URL is set).
func Emit(e Event) {
	e.ID = randHex(8)
	e.TS = float64(time.Now().UnixNano()) / 1e9
	for k, v := range e.Tokens {
		if v == "" {
			delete(e.Tokens, k)
		}
	}
	mark := "OK  "
	if !e.OK {
		mark = "FAIL"
	}
	log.Printf("[trace %.8s] %s %-14s %s -> %s %s", e.TraceID, mark, e.Kind, e.Src, e.Dst, e.Summary)
	if observerURL == "" {
		return
	}
	select {
	case traceQueue <- e:
	default: // never block the request path on the demo UI
	}
}

// NewTraceparent returns a fresh W3C traceparent header value.
func NewTraceparent() string { return "00-" + randHex(16) + "-" + randHex(8) + "-01" }

// TraceID extracts the trace id from a traceparent value. Bare labels such as
// "startup" or "attacks" are accepted as named demo traces (display only).
func TraceID(tp string) string {
	parts := strings.Split(tp, "-")
	if len(parts) == 4 && len(parts[1]) == 32 {
		return parts[1]
	}
	if isLabel(tp) {
		return tp
	}
	return "untraced"
}

// ChildTraceparent keeps the trace id and mints a new span id.
func ChildTraceparent(tp string) string {
	if isLabel(tp) {
		return tp
	}
	if id := TraceID(tp); id != "untraced" {
		return "00-" + id + "-" + randHex(8) + "-01"
	}
	return NewTraceparent()
}

func isLabel(tp string) bool {
	if tp == "" || len(tp) > 32 {
		return false
	}
	for _, r := range tp {
		if !(r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
