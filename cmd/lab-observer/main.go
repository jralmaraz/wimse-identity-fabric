// lab-observer is the transaction viewer of the local multi-cloud lab.
// Every lab component posts an event per transaction; the UI renders them as
// a live sequence diagram with decoded tokens and verification checks, and
// can drive the demo (checkout, policy shortcut, attack suite).
//
// DEMO ONLY: it receives raw tokens. Do not run it outside a lab.
package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/internal/lab"
)

//go:embed ui/index.html
var ui embed.FS

type store struct {
	mu     sync.Mutex
	events []lab.Event
	subs   map[chan lab.Event]struct{}
}

func (s *store) add(e lab.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	if len(s.events) > 3000 {
		s.events = s.events[len(s.events)-3000:]
	}
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

func (s *store) snapshot() []lab.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]lab.Event(nil), s.events...)
}

func main() {
	st := &store{subs: map[chan lab.Event]struct{}{}}
	ordersURL := envOr("ORDERS_URL", "http://orders:8080")
	runner := &attackRunner{
		paymentsURL: envOr("PAYMENTS_URL", "http://payments:8080"),
		ledgerURL:   envOr("LEDGER_URL", "http://ledger:8080"),
		ordersURL:   ordersURL,
		store:       st,
		http:        &http.Client{Timeout: 20 * time.Second},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		b, _ := ui.ReadFile("ui/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { lab.WriteJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		var e lab.Event
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&e); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		st.add(e)
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, _ *http.Request) { lab.WriteJSON(w, 200, st.snapshot()) })
	mux.HandleFunc("POST /api/clear", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		st.events = nil
		st.mu.Unlock()
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /api/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(200)
		flusher.Flush() // lets the browser's EventSource report "open" immediately
		ch := make(chan lab.Event, 64)
		st.mu.Lock()
		st.subs[ch] = struct{}{}
		st.mu.Unlock()
		defer func() { st.mu.Lock(); delete(st.subs, ch); st.mu.Unlock() }()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case e := <-ch:
				b, _ := json.Marshal(e)
				fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			case <-ticker.C:
				fmt.Fprint(w, ": keep-alive\n\n")
				flusher.Flush()
			}
		}
	})
	mux.HandleFunc("POST /api/run/checkout", func(w http.ResponseWriter, r *http.Request) {
		proxy(w, runner.http, ordersURL+"/checkout", r.Body)
	})
	mux.HandleFunc("POST /api/run/direct-ledger", func(w http.ResponseWriter, _ *http.Request) {
		proxy(w, runner.http, ordersURL+"/debug/direct-ledger", nil)
	})
	mux.HandleFunc("POST /api/run/attacks", func(w http.ResponseWriter, _ *http.Request) {
		results, err := runner.run()
		if err != nil {
			lab.WriteJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		lab.WriteJSON(w, 200, results)
	})

	addr := ":" + envOr("PORT", "8080")
	log.Printf("lab-observer on %s (orders=%s)", addr, ordersURL)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func proxy(w http.ResponseWriter, client *http.Client, url string, body io.Reader) {
	var b []byte
	if body != nil {
		b, _ = io.ReadAll(io.LimitReader(body, 16<<10))
	}
	if len(b) == 0 {
		b = []byte("{}")
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		lab.WriteJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
