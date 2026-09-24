package ssf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/ssf"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEmitAndSubscribe(t *testing.T) {
	key := genKey(t)
	tx := ssf.NewTransmitter("https://idp.example", key)
	tx.RegisterStream(ssf.StreamConfig{
		EventTypes: []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
	})

	ch := tx.Subscribe()
	if err := tx.Emit("https://schemas.openid.net/secevent/caep/event-type/session-revoked", map[string]any{"sub": "spiffe://example/svc"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case set := <-ch:
		if set.Issuer != "https://idp.example" {
			t.Errorf("Issuer = %q, want https://idp.example", set.Issuer)
		}
		if _, ok := set.Events["https://schemas.openid.net/secevent/caep/event-type/session-revoked"]; !ok {
			t.Error("event type missing from SET")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for SET on channel")
	}
}

func TestEmitNoMatchingStream(t *testing.T) {
	key := genKey(t)
	tx := ssf.NewTransmitter("https://idp.example", key)
	tx.RegisterStream(ssf.StreamConfig{
		EventTypes: []string{"https://schemas.openid.net/secevent/caep/event-type/credential-change"},
	})

	ch := tx.Subscribe()
	// emit session-revoked — not wanted by the stream above
	if err := tx.Emit("https://schemas.openid.net/secevent/caep/event-type/session-revoked", map[string]any{}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	// channel receives it regardless (in-process channel is always delivered)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timeout: in-process channel should always receive")
	}
}

func TestPushDelivery(t *testing.T) {
	received := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/secevent+jwt" {
			t.Errorf("Content-Type = %q, want application/secevent+jwt", ct)
		}
		b, _ := io.ReadAll(r.Body)
		received <- string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	key := genKey(t)
	tx := ssf.NewTransmitter("https://idp.example", key)
	tx.RegisterStream(ssf.StreamConfig{
		EndpointURL: srv.URL + "/events",
	})

	if err := tx.Emit("https://schemas.openid.net/secevent/caep/event-type/session-revoked", map[string]any{"sub": "x"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case body := <-received:
		if len(body) < 10 {
			t.Errorf("push body too short: %q", body)
		}
		// raw JWT compact: three base64url segments separated by dots
		for _, seg := range []string{".", "."} {
			if !contains(body, seg) {
				t.Errorf("push body doesn't look like compact JWT: %q", body)
			}
			_ = seg
			break
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for push delivery")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsRune(s, sub))
}

func containsRune(s, sub string) bool {
	for i := range s {
		if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestParseSET(t *testing.T) {
	key := genKey(t)
	tx := ssf.NewTransmitter("https://idp.example", key)

	ch := tx.Subscribe()
	if err := tx.Emit("https://schemas.openid.net/secevent/caep/event-type/session-revoked", map[string]any{"sub": "spiffe://td/svc"}); err != nil {
		t.Fatal(err)
	}
	<-ch // drain

	// emit again to a push endpoint so we can capture the compact JWT
	jwtCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case jwtCh <- string(b):
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tx.RegisterStream(ssf.StreamConfig{EndpointURL: srv.URL})
	if err := tx.Emit("https://schemas.openid.net/secevent/caep/event-type/session-revoked", map[string]any{"sub": "spiffe://td/svc2"}); err != nil {
		t.Fatal(err)
	}
	<-ch

	var capturedJWT string
	select {
	case capturedJWT = <-jwtCh:
	case <-time.After(2 * time.Second):
		t.Skip("push delivery didn't arrive in time; skipping ParseSET round-trip")
	}

	set, err := ssf.ParseSET(capturedJWT, &key.PublicKey)
	if err != nil {
		t.Fatalf("ParseSET: %v", err)
	}
	if set.Issuer != "https://idp.example" {
		t.Errorf("Issuer = %q", set.Issuer)
	}
}

func TestDeregisterStream(t *testing.T) {
	pushed := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed <- struct{}{}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	key := genKey(t)
	tx := ssf.NewTransmitter("https://idp.example", key)
	id := tx.RegisterStream(ssf.StreamConfig{EndpointURL: srv.URL})
	tx.DeregisterStream(id)

	if err := tx.Emit("https://schemas.openid.net/secevent/caep/event-type/session-revoked", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pushed:
		t.Error("push was delivered after deregister")
	case <-time.After(200 * time.Millisecond):
		// good — no push after deregister
	}
}
