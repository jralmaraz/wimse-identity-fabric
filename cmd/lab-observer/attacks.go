package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/internal/lab"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wpt"
)

// attackRunner replays and forges tokens captured from the last successful
// orders → payments call, and checks each attempt is rejected for the right reason.
type attackRunner struct {
	paymentsURL, ledgerURL, ordersURL string
	store                             *store
	http                              *http.Client
}

type attackResult struct {
	Name     string `json:"name"`
	Expected int    `json:"expected"`
	Observed int    `json:"observed"`
	Blocked  bool   `json:"blocked"`
	Reason   string `json:"reason"`
}

type captured struct{ wit, wpt, txn, sub string }

func (a *attackRunner) capture() (*captured, error) {
	events := a.store.snapshot()
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Kind == "wimse-call" && e.OK && e.Dst == "payments" && e.Tokens["WIT"] != "" {
			c := &captured{wit: e.Tokens["WIT"], wpt: e.Tokens["WPT"], txn: e.Tokens["Txn-Token"]}
			var claims struct {
				Sub string `json:"sub"`
			}
			if err := decodePayload(c.wit, &claims); err != nil {
				return nil, err
			}
			c.sub = claims.Sub
			return c, nil
		}
	}
	return nil, errors.New("no successful orders → payments call captured yet")
}

func (a *attackRunner) run() ([]attackResult, error) {
	c, err := a.capture()
	if err != nil { // run a legitimate checkout first so there is traffic to steal
		if resp, perr := a.http.Post(a.ordersURL+"/checkout", "application/json", strings.NewReader("{}")); perr == nil {
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
		if c, err = a.capture(); err != nil {
			return nil, err
		}
	}
	charge := a.paymentsURL + "/charge"
	attacker, _ := keys.GenerateECKeyPair()

	var results []attackResult
	add := func(name string, expected int, status int, reason string) {
		r := attackResult{Name: name, Expected: expected, Observed: status, Blocked: status == expected, Reason: reason}
		results = append(results, r)
		verdict := "BLOCKED as expected"
		if !r.Blocked {
			verdict = fmt.Sprintf("NOT blocked as expected (wanted %d)", expected)
		}
		lab.Emit(lab.Event{TraceID: "attacks", Kind: "attack", Src: "attacker", Dst: targetName(name), OK: r.Blocked,
			Status: status, Summary: fmt.Sprintf("%s → %d: %s – %s", name, status, verdict, reason)})
	}

	// 1. Bearer use of a stolen WIT.
	s, why := a.send(charge, map[string]string{lab.HeaderWIT: c.wit, lab.HeaderTxn: c.txn})
	add("Stolen WIT used as a bearer token (no proof)", 401, s, why)

	// 2. Exact replay of a captured request.
	s, why = a.send(charge, map[string]string{lab.HeaderWIT: c.wit, "Authorization": "WPT " + c.wpt, lab.HeaderTxn: c.txn})
	add("Replay of a captured WIT + WPT", 401, s, why)

	// 3. Captured proof sent to a different service.
	s, why = a.send(a.ledgerURL+"/entries", map[string]string{lab.HeaderWIT: c.wit, "Authorization": "WPT " + c.wpt, lab.HeaderTxn: c.txn})
	add("Captured proof redirected to ledger", 401, s, why)

	// 4. Stolen WIT with a proof signed by the attacker's own key.
	forged, _ := wpt.Generate(wpt.GenerateOptions{TargetURI: charge, WIT: c.wit, WorkloadKey: attacker.Private, TxnToken: c.txn})
	s, why = a.send(charge, map[string]string{lab.HeaderWIT: c.wit, "Authorization": "WPT " + forged, lab.HeaderTxn: c.txn})
	add("Stolen WIT + attacker-signed WPT", 401, s, why)

	// 5. Tampered Txn-Token (amount raised) with the original proof.
	s, why = a.send(charge, map[string]string{lab.HeaderWIT: c.wit, "Authorization": "WPT " + c.wpt, lab.HeaderTxn: tamperTxn(c.txn)})
	add("Txn-Token tampered (amount → 1,000,000)", 401, s, why)

	// 6. Rogue issuer mints a WIT for the real orders identity.
	issuerID := claimOf(c.wit, "iss")
	rogue, _ := wit.NewIssuer(issuerID, attacker.Private, time.Hour).Issue(wit.IssueOptions{Subject: c.sub, WorkloadKey: attacker.Public})
	proof, _ := wpt.Generate(wpt.GenerateOptions{TargetURI: charge, WIT: rogue, WorkloadKey: attacker.Private, TxnToken: c.txn})
	s, why = a.send(charge, map[string]string{lab.HeaderWIT: rogue, "Authorization": "WPT " + proof, lab.HeaderTxn: c.txn})
	add("WIT for 'orders' minted by a rogue issuer", 400, s, why)

	// 7. Identity from a trust domain nobody federated with.
	evil, _ := wit.NewIssuer("https://idp.evil.example", attacker.Private, time.Hour).Issue(wit.IssueOptions{
		Subject: "spiffe://evil.example/ns/shop/sa/orders", WorkloadKey: attacker.Public})
	proof, _ = wpt.Generate(wpt.GenerateOptions{TargetURI: charge, WIT: evil, WorkloadKey: attacker.Private, TxnToken: c.txn})
	s, why = a.send(charge, map[string]string{lab.HeaderWIT: evil, "Authorization": "WPT " + proof, lab.HeaderTxn: c.txn})
	add("WIT from unfederated domain evil.example", 400, s, why)

	// 8. Legitimate identity, wrong path: orders skips payments and calls ledger.
	resp, err := a.http.Post(a.ordersURL+"/debug/direct-ledger", "application/json", strings.NewReader("{}"))
	if err == nil {
		var out struct {
			Status   int            `json:"ledger_status"`
			Response map[string]any `json:"ledger_response"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		detail, _ := out.Response["detail"].(string)
		add("orders (authenticated) calls ledger directly", 403, out.Status, detail)
	}
	return results, nil
}

func (a *attackRunner) send(url string, headers map[string]string) (int, string) {
	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte(`{"amount":"1000000"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(lab.HeaderDemoActor, "attacker")
	req.Header.Set("traceparent", "attacks") // named demo trace
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var p struct {
		Code   string `json:"title"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(b, &p)
	return resp.StatusCode, strings.TrimSpace(p.Code + ": " + p.Detail)
}

func targetName(attack string) string {
	if strings.Contains(attack, "ledger") {
		return "ledger"
	}
	return "payments"
}

// tamperTxn rewrites the payload but keeps the original signature.
func tamperTxn(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return tok
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tok
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return tok
	}
	if azd, ok := m["azd"].([]any); ok && len(azd) > 0 {
		if d, ok := azd[0].(map[string]any); ok {
			if cl, ok := d["claims"].(map[string]any); ok {
				cl["amount"] = "1000000.00"
			}
		}
	}
	nb, _ := json.Marshal(m)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(nb) + "." + parts[2]
}

func decodePayload(tok string, v any) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func claimOf(tok, claim string) string {
	var m map[string]any
	if decodePayload(tok, &m) != nil {
		return ""
	}
	s, _ := m[claim].(string)
	return s
}
