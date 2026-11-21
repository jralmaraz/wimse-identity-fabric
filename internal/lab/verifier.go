package lab

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/txntoken"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wpt"
)

// Header names / schemes.
const (
	HeaderWIT = "Workload-Identity-Token" // draft-ietf-wimse-workload-creds-02 §5.1
	HeaderTxn = "Txn-Token"               // draft-ietf-oauth-transaction-tokens
	WPTScheme = "WPT"                     // draft-ietf-wimse-wpt-02: Authorization: WPT <jwt>
	// HeaderDemoActor lets the attack runner label itself in the UI. Display only –
	// never used for any security decision.
	HeaderDemoActor = "X-Demo-Actor"
)

// MaxWPTLifetime rejects proofs whose exp is unreasonably far in the future.
const MaxWPTLifetime = 5*time.Minute + 5*time.Second

// Caller is the authenticated (and authorized) peer of a request.
type Caller struct {
	ID        string
	WIT       *wit.Claims
	WPT       *wpt.Claims
	TxnRaw    string
	Txn       *txntoken.Claims
	Checks    []Check
	Traceprnt string
}

// Rejection is a failed verification, rendered as RFC 9457 problem details.
type Rejection struct {
	Status int
	Code   string
	Detail string
	Checks []Check
}

func (r *Rejection) Error() string { return r.Code + ": " + r.Detail }

// Verifier authenticates WIT + WPT (+ optional Txn-Token) and applies a
// path-level authorization policy.
type Verifier struct {
	Service string // name shown in the observer, e.g. "payments"
	// SelfURL is this service's externally used base URL, from trusted
	// configuration. The expected WPT `aud` is SelfURL + request path; the
	// Host / X-Forwarded-Host headers are never trusted for this (wpt §3.1).
	SelfURL     string
	Bundle      *TrustBundle
	Policy      map[string][]string // request path -> allowed workload IDs
	TxnIssuer   string              // issuer ID of the trusted Txn-Token Service ("" = no Txn-Tokens)
	TxnAudience string
	RequireTxn  bool
	wpt         *wpt.Validator
}

// NewVerifier builds a verifier with an in-memory jti replay store.
func NewVerifier(service, selfURL string, bundle *TrustBundle, policy map[string][]string) *Verifier {
	return &Verifier{Service: service, SelfURL: strings.TrimRight(selfURL, "/"), Bundle: bundle,
		Policy: policy, wpt: wpt.NewValidator()}
}

type checks struct{ items []Check }

func (c *checks) ok(name, detail string) { c.items = append(c.items, Check{name, true, detail}) }
func (c *checks) fail(status int, code, name, detail string) *Rejection {
	c.items = append(c.items, Check{name, false, detail})
	return &Rejection{Status: status, Code: code, Detail: detail, Checks: c.items}
}

// Verify runs all checks. WIT problems -> 400 (workload-creds §5.2), WPT
// problems -> 401 + WWW-Authenticate: WPT (wpt-02), policy -> 403.
func (v *Verifier) Verify(r *http.Request) (*Caller, *Rejection) {
	c := &checks{}

	witVals := r.Header.Values(HeaderWIT)
	if len(witVals) != 1 {
		return nil, c.fail(400, "missing-wit", "WIT header", fmt.Sprintf("expected exactly one %s header, got %d", HeaderWIT, len(witVals)))
	}
	witRaw := strings.TrimSpace(witVals[0])

	authVals := r.Header.Values("Authorization")
	if len(authVals) != 1 {
		return nil, c.fail(401, "missing-wpt", "WPT present",
			"no Authorization: WPT proof – a WIT alone is never accepted (it is not a bearer token)")
	}
	scheme, wptRaw, _ := strings.Cut(strings.TrimSpace(authVals[0]), " ")
	if !strings.EqualFold(scheme, WPTScheme) || strings.TrimSpace(wptRaw) == "" {
		return nil, c.fail(401, "missing-wpt", "WPT present", fmt.Sprintf("Authorization scheme %q is not WPT", scheme))
	}
	wptRaw = strings.TrimSpace(wptRaw)
	c.ok("Headers", "one Workload-Identity-Token + one Authorization: WPT")

	// ---- WIT ---------------------------------------------------------------
	unv, err := decodeClaims(witRaw)
	if err != nil {
		return nil, c.fail(400, "malformed-wit", "WIT structure", err.Error())
	}
	sub, _ := unv["sub"].(string)
	domain, err := TrustDomainOf(sub)
	if err != nil {
		return nil, c.fail(400, "invalid-wit", "WIT sub", fmt.Sprintf("bad workload identifier %q: %v", sub, err))
	}
	c.ok("WIT sub", sub+" → trust domain "+domain)
	issuer, federated := v.Bundle.Issuer(domain)
	if !federated {
		return nil, c.fail(400, "untrusted-domain", "Trust domain federated",
			fmt.Sprintf("no trust anchors configured for %q (federated: %s)", domain, strings.Join(v.Bundle.Domains(), ", ")))
	}
	c.ok("Trust domain federated", domain+" anchors from "+issuer+"/.well-known/jwks.json")

	witRes, err := v.validateWIT(witRaw, domain, issuer)
	if err != nil {
		return nil, c.fail(400, "invalid-wit", "WIT signature, typ, iss, exp (pkg/wit)", err.Error())
	}
	c.ok("WIT signature, typ, iss, exp (pkg/wit)", fmt.Sprintf("typ=wit+jwt ES256 iss=%s, expires in %s",
		witRes.Claims.Issuer, time.Until(witRes.Claims.ExpiresAt.Time).Round(time.Second)))
	c.ok("WIT cnf.jwk", "workload public key bound to "+ShortName(sub))

	// ---- Txn-Token presence --------------------------------------------------
	txnVals := r.Header.Values(HeaderTxn)
	if len(txnVals) > 1 {
		return nil, c.fail(400, "invalid-txn-token", "Txn-Token header", "more than one Txn-Token header")
	}
	txnRaw := ""
	if len(txnVals) == 1 {
		txnRaw = strings.TrimSpace(txnVals[0])
	}
	if v.RequireTxn && txnRaw == "" {
		return nil, c.fail(400, "missing-txn-token", "Txn-Token present", "this endpoint requires a Txn-Token")
	}

	// ---- WPT: explain each binding, then let pkg/wpt make the decision ------
	expectedAud := v.SelfURL + r.URL.Path
	if wc, err := decodeClaims(wptRaw); err == nil {
		if aud := audList(wc["aud"]); !contains(aud, expectedAud) {
			return nil, v.wptFail(c, "WPT aud = target URI", fmt.Sprintf("aud %v does not match this endpoint %s", aud, expectedAud))
		}
		c.ok("WPT aud = target URI", expectedAud)
		if wth, _ := wc["wth"].(string); wth != sha256B64(witRaw) {
			return nil, v.wptFail(c, "wth binds WIT", "wth does not match SHA-256 of the presented WIT")
		}
		c.ok("wth binds WIT", "wth = SHA-256(WIT)")
		tth, _ := wc["tth"].(string)
		switch {
		case txnRaw == "" && tth != "":
			return nil, v.wptFail(c, "tth binds Txn-Token", "WPT carries tth but no Txn-Token was sent")
		case txnRaw != "" && tth != sha256B64(txnRaw):
			return nil, v.wptFail(c, "tth binds Txn-Token", "tth does not match the presented Txn-Token (swapped or tampered)")
		case txnRaw != "":
			c.ok("tth binds Txn-Token", "tth = SHA-256(Txn-Token)")
		}
		if exp, ok := wc["exp"].(float64); ok && time.Until(time.Unix(int64(exp), 0)) > MaxWPTLifetime {
			return nil, v.wptFail(c, "WPT lifetime", "WPT expiry unreasonably far in the future")
		}
	}
	wptClaims, err := v.wpt.Validate(wpt.ValidateOptions{
		WPTString: wptRaw, WITString: witRaw, WorkloadPublicKey: witRes.WorkloadKey,
		RequestURI: expectedAud, CheckReplay: true, TxnToken: txnRaw,
	})
	if err != nil {
		name := "WPT proof of possession (pkg/wpt)"
		if errors.Is(err, wpt.ErrReplayed) {
			name = "WPT jti not replayed"
		}
		return nil, v.wptFail(c, name, err.Error())
	}
	c.ok("WPT proof of possession (pkg/wpt)", "signed with the key in WIT cnf.jwk; typ, exp, aud, wth ok")
	c.ok("WPT jti not replayed", "jti "+trunc(wptClaims.ID, 10)+"… recorded")

	// ---- Txn-Token -------------------------------------------------------------
	var txn *txntoken.Claims
	if txnRaw != "" {
		if txn, err = v.validateTxn(txnRaw); err != nil {
			return nil, c.fail(400, "invalid-txn-token", "Txn-Token (pkg/txntoken)", err.Error())
		}
		reqWL := ""
		if txn.ReqCtx != nil {
			reqWL = txn.ReqCtx.ReqWL
		}
		c.ok("Txn-Token (pkg/txntoken)", fmt.Sprintf("txn=%s… user=%s started by %s", trunc(txn.Txn, 8), txn.Subject, ShortName(reqWL)))
	}

	// ---- Authorization ---------------------------------------------------------
	if !contains(v.Policy[r.URL.Path], sub) {
		return nil, c.fail(403, "forbidden", "Authorization policy",
			fmt.Sprintf("%s is authenticated but NOT allowed to call %s %s", sub, r.Method, r.URL.Path))
	}
	c.ok("Authorization policy", fmt.Sprintf("%s may call %s %s", ShortName(sub), r.Method, r.URL.Path))

	return &Caller{ID: sub, WIT: witRes.Claims, WPT: wptClaims, TxnRaw: txnRaw, Txn: txn, Checks: c.items}, nil
}

func (v *Verifier) wptFail(c *checks, name, detail string) *Rejection {
	return c.fail(401, "invalid-wpt", name, detail)
}

func (v *Verifier) validateWIT(raw, domain, issuer string) (*wit.ValidationResult, error) {
	var lastErr error
	for _, refresh := range []bool{false, true} { // retry once with fresh JWKS (rotation)
		pubs, err := v.Bundle.Keys(domain, refresh)
		if err != nil {
			return nil, err
		}
		for _, pub := range pubs {
			res, err := wit.NewValidator(issuer, pub).Validate(raw)
			if err == nil {
				return res, nil
			}
			lastErr = err
		}
	}
	return nil, lastErr
}

func (v *Verifier) validateTxn(raw string) (*txntoken.Claims, error) {
	if v.TxnIssuer == "" {
		return nil, errors.New("this service trusts no Txn-Token Service")
	}
	domain, ok := v.Bundle.DomainOfIssuer(v.TxnIssuer)
	if !ok {
		return nil, fmt.Errorf("Txn-Token Service %s is not in the trust bundle", v.TxnIssuer)
	}
	pubs, err := v.Bundle.Keys(domain, false)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, pub := range pubs {
		claims, err := txntoken.NewValidator(v.TxnIssuer, pub).Validate(raw)
		if err != nil {
			lastErr = err
			continue
		}
		if v.TxnAudience != "" && !contains(claims.Audience, v.TxnAudience) {
			return nil, fmt.Errorf("Txn-Token aud %v does not include %s", claims.Audience, v.TxnAudience)
		}
		return claims, nil
	}
	return nil, lastErr
}

// Handler wraps a handler with verification, observer events and problem responses.
func (v *Verifier) Handler(next func(http.ResponseWriter, *http.Request, *Caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tp := r.Header.Get("traceparent")
		tokens := map[string]string{
			"WIT":       r.Header.Get(HeaderWIT),
			"WPT":       strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), WPTScheme+" ")),
			"Txn-Token": r.Header.Get(HeaderTxn),
		}
		caller, rej := v.Verify(r)
		src := r.Header.Get(HeaderDemoActor)
		if rej != nil {
			if src == "" {
				src = claimedCaller(tokens["WIT"])
			}
			Emit(Event{TraceID: TraceID(tp), Kind: "wimse-call", Src: src, Dst: v.Service, Method: r.Method,
				Path: r.URL.Path, Status: rej.Status, OK: false, Summary: fmt.Sprintf("REJECTED %d %s: %s", rej.Status, rej.Code, rej.Detail),
				Tokens: tokens, Checks: rej.Checks})
			WriteProblem(w, rej)
			return
		}
		if src == "" {
			src = ShortName(caller.ID)
		}
		Emit(Event{TraceID: TraceID(tp), Kind: "wimse-call", Src: src, Dst: v.Service, Method: r.Method,
			Path: r.URL.Path, Status: 200, OK: true, Summary: "authenticated " + caller.ID, Tokens: tokens, Checks: caller.Checks})
		caller.Traceprnt = tp
		next(w, r, caller)
	}
}

// WriteProblem renders an RFC 9457 problem details response.
func WriteProblem(w http.ResponseWriter, rej *Rejection) {
	if rej.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", WPTScheme)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(rej.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "https://wimse-identity-fabric.local/problems/" + rej.Code,
		"title":  strings.ReplaceAll(rej.Code, "-", " "),
		"status": rej.Status,
		"detail": rej.Detail,
		"checks": rej.Checks,
	})
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- small helpers -------------------------------------------------------------

func decodeClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS (want 3 segments)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload is not base64url: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("payload is not JSON: %w", err)
	}
	return m, nil
}

func claimedCaller(witRaw string) string {
	if m, err := decodeClaims(witRaw); err == nil {
		if s, ok := m["sub"].(string); ok {
			return ShortName(s) + "?"
		}
	}
	return "unknown"
}

func audList(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func sha256B64(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
