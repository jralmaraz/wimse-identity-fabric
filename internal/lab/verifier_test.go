package lab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/txntoken"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wpt"
)

const (
	ordersID   = "spiffe://aws.wimse.local/ns/shop/sa/orders"
	paymentsID = "spiffe://gcp.wimse.local/ns/shop/sa/payments"
	txnAud     = "urn:wimse-lab:shop"
)

type domainIssuer struct {
	kp  *keys.ECKeyPair
	srv *httptest.Server
}

func newDomainIssuer(t *testing.T) *domainIssuer {
	t.Helper()
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwk, _ := keys.PublicKeyToJWK(kp.Public, "k1")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
	t.Cleanup(srv.Close)
	return &domainIssuer{kp: kp, srv: srv}
}

func (d *domainIssuer) wit(t *testing.T, sub string, workload *keys.ECKeyPair) string {
	t.Helper()
	tok, err := wit.NewIssuer(d.srv.URL, d.kp.Private, time.Hour).Issue(wit.IssueOptions{Subject: sub, WorkloadKey: workload.Public})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type fixture struct {
	aws, gcp *domainIssuer
	orders   *keys.ECKeyPair
	witA     string
	txn      string
	target   *httptest.Server
}

// newFixture: payments (verifier) trusts aws + gcp; only orders may call /charge.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{aws: newDomainIssuer(t), gcp: newDomainIssuer(t)}
	f.orders, _ = keys.GenerateECKeyPair()
	f.witA = f.aws.wit(t, ordersID, f.orders)
	var err error
	f.txn, err = txntoken.NewIssuer(f.aws.srv.URL, f.aws.kp.Private, time.Minute).Issue(txntoken.IssueOptions{
		Subject: "alice@example.com", Audiences: []string{txnAud}, ReqCtx: &txntoken.RequestContext{ReqWL: ordersID}})
	if err != nil {
		t.Fatal(err)
	}
	bundle := NewTrustBundle(map[string]string{"aws.wimse.local": f.aws.srv.URL, "gcp.wimse.local": f.gcp.srv.URL})

	mux := http.NewServeMux()
	f.target = httptest.NewUnstartedServer(mux)
	f.target.Start()
	t.Cleanup(f.target.Close)
	v := NewVerifier("payments", f.target.URL, bundle, map[string][]string{"/charge": {ordersID}})
	v.TxnIssuer, v.TxnAudience, v.RequireTxn = f.aws.srv.URL, txnAud, true
	mux.HandleFunc("POST /charge", v.Handler(func(w http.ResponseWriter, _ *http.Request, c *Caller) {
		WriteJSON(w, 200, map[string]string{"caller": c.ID, "user": c.Txn.Subject})
	}))
	mux.HandleFunc("POST /refund", v.Handler(func(w http.ResponseWriter, _ *http.Request, _ *Caller) { w.WriteHeader(200) }))
	return f
}

func (f *fixture) wpt(t *testing.T, path string, key *keys.ECKeyPair, witTok, txn string) string {
	t.Helper()
	p, err := wpt.Generate(wpt.GenerateOptions{TargetURI: f.target.URL + path, WIT: witTok, WorkloadKey: key.Private, TxnToken: txn})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fixture) post(t *testing.T, path string, h map[string]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.target.URL+path, strings.NewReader("{}"))
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode == 401 && resp.Header.Get("WWW-Authenticate") != "WPT" {
		t.Errorf("401 without WWW-Authenticate: WPT challenge")
	}
	return resp.StatusCode, body
}

func headers(witTok, proof, txn string) map[string]string {
	h := map[string]string{HeaderWIT: witTok, HeaderTxn: txn}
	if proof != "" {
		h["Authorization"] = "WPT " + proof
	}
	return h
}

func TestVerifierAcceptsCrossDomainCall(t *testing.T) {
	f := newFixture(t)
	status, body := f.post(t, "/charge", headers(f.witA, f.wpt(t, "/charge", f.orders, f.witA, f.txn), f.txn))
	if status != 200 || body["caller"] != ordersID || body["user"] != "alice@example.com" {
		t.Fatalf("want 200 for orders, got %d %v", status, body)
	}
}

func TestVerifierRejections(t *testing.T) {
	f := newFixture(t)
	attacker, _ := keys.GenerateECKeyPair()
	rogue := &domainIssuer{kp: attacker, srv: f.aws.srv} // signs with the wrong key but claims the aws issuer
	evil := newDomainIssuer(t)
	evilWIT := evil.wit(t, "spiffe://evil.example/ns/shop/sa/orders", attacker)
	gcpWIT := f.gcp.wit(t, paymentsID, attacker)
	rogueWIT := rogue.wit(t, ordersID, attacker)
	good := f.wpt(t, "/charge", f.orders, f.witA, f.txn)

	cases := []struct {
		name   string
		path   string
		h      map[string]string
		status int
		code   string
	}{
		{"WIT without proof (bearer use)", "/charge", headers(f.witA, "", f.txn), 401, "missing-wpt"},
		{"proof signed by another key", "/charge", headers(f.witA, f.wpt(t, "/charge", attacker, f.witA, f.txn), f.txn), 401, "invalid-wpt"},
		{"proof for another endpoint", "/charge", headers(f.witA, f.wpt(t, "/refund", f.orders, f.witA, f.txn), f.txn), 401, "invalid-wpt"},
		{"tth present but Txn-Token swapped", "/charge", headers(f.witA, good, f.txn+"x"), 401, "invalid-wpt"},
		{"rogue issuer key", "/charge", headers(rogueWIT, f.wpt(t, "/charge", attacker, rogueWIT, f.txn), f.txn), 400, "invalid-wit"},
		{"unfederated trust domain", "/charge", headers(evilWIT, f.wpt(t, "/charge", attacker, evilWIT, f.txn), f.txn), 400, "untrusted-domain"},
		{"authenticated but not authorized", "/charge", headers(gcpWIT, f.wpt(t, "/charge", attacker, gcpWIT, f.txn), f.txn), 403, "forbidden"},
		{"policy has no entry for path", "/refund", headers(f.witA, f.wpt(t, "/refund", f.orders, f.witA, f.txn), f.txn), 403, "forbidden"},
		{"missing Txn-Token", "/charge", headers(f.witA, f.wpt(t, "/charge", f.orders, f.witA, ""), ""), 400, "missing-txn-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := f.post(t, tc.path, tc.h)
			if status != tc.status || !strings.HasSuffix(body["type"].(string), "/"+tc.code) {
				t.Fatalf("want %d %s, got %d %v", tc.status, tc.code, status, body)
			}
		})
	}
}

func TestVerifierDetectsReplay(t *testing.T) {
	f := newFixture(t)
	h := headers(f.witA, f.wpt(t, "/charge", f.orders, f.witA, f.txn), f.txn)
	if status, body := f.post(t, "/charge", h); status != 200 {
		t.Fatalf("first use: %d %v", status, body)
	}
	status, body := f.post(t, "/charge", h)
	if status != 401 || !strings.Contains(body["detail"].(string), "replay") {
		t.Fatalf("replay: want 401 replay, got %d %v", status, body)
	}
}

func TestTrustDomainOf(t *testing.T) {
	good := map[string]string{ordersID: "aws.wimse.local", "wimse://Example.com/svc": "example.com"}
	for id, want := range good {
		if got, err := TrustDomainOf(id); err != nil || got != want {
			t.Errorf("%s: got %q %v", id, got, err)
		}
	}
	for _, id := range []string{"https://aws.wimse.local/x", "spiffe://aws.wimse.local", "spiffe://u@d/x", "spiffe://d:443/x", "spiffe://d/x?q=1"} {
		if _, err := TrustDomainOf(id); err == nil {
			t.Errorf("%s: expected error", id)
		}
	}
}
