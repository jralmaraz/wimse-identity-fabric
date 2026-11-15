package lab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wpt"
)

// AttestTyp is the JOSE typ of the self-signed attestation request a workload
// sends to its issuer. Signing it with the to-be-certified key proves
// possession of that key (CSR-style) before the issuer binds it into cnf.jwk.
const AttestTyp = "wimse-attest+jwt"

// Evidence is one piece of platform attestation evidence.
type Evidence struct {
	Type string            `json:"type"`           // aws-sts | docker | join-token
	Data map[string]string `json:"data,omitempty"` // e.g. {"url": <presigned GetCallerIdentity>}
}

// EvidenceFunc gathers fresh evidence for each attestation.
type EvidenceFunc func() ([]Evidence, error)

// Agent is the workload side of WIMSE: it owns the workload key (which never
// leaves the process), obtains a WIT from its trust domain's issuer through
// attestation, and signs a fresh WPT for every outbound request.
type Agent struct {
	Name      string
	IssuerURL string
	evidence  EvidenceFunc
	key       *keys.ECKeyPair
	client    *http.Client

	mu     sync.Mutex
	wit    string
	sub    string
	expiry time.Time
}

// NewAgent creates an agent with a fresh ES256 key pair.
func NewAgent(name, issuerURL string, ev EvidenceFunc) (*Agent, error) {
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		return nil, err
	}
	return &Agent{Name: name, IssuerURL: strings.TrimRight(issuerURL, "/"), evidence: ev, key: kp,
		client: &http.Client{Timeout: 20 * time.Second}}, nil
}

// ID returns the workload identifier from the current WIT ("" before attestation).
func (a *Agent) ID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sub
}

// WIT returns a valid WIT, (re-)attesting when missing or within 5 minutes of expiry.
func (a *Agent) WIT(tp string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.wit != "" && time.Until(a.expiry) > 5*time.Minute {
		return a.wit, nil
	}
	return a.attestLocked(tp)
}

// AttestWithRetry blocks until the issuer issues a WIT or maxWait passes.
func (a *Agent) AttestWithRetry(maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	for {
		_, err := a.WIT("startup")
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		fmt.Printf("%s: waiting for issuer %s (%v)\n", a.Name, a.IssuerURL, err)
		time.Sleep(3 * time.Second)
	}
}

func (a *Agent) attestLocked(tp string) (string, error) {
	ev, err := a.evidence()
	if err != nil {
		return "", fmt.Errorf("gather evidence: %w", err)
	}
	jwk, err := keys.PublicKeyToJWK(a.key.Public, a.Name+"-key")
	if err != nil {
		return "", err
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": a.IssuerURL + "/attest", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"jti": randHex(16), "workload": a.Name, "evidence": ev,
	})
	tok.Header["typ"] = AttestTyp
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(a.key.Private)
	if err != nil {
		return "", err
	}
	req, _ := http.NewRequest(http.MethodPost, a.IssuerURL+"/attest", strings.NewReader(signed))
	req.Header.Set("Content-Type", "application/jwt")
	req.Header.Set("traceparent", ChildTraceparent(tp))
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("attestation rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		WIT string `json:"wit"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.WIT == "" {
		return "", fmt.Errorf("bad attestation response: %s", body)
	}
	claims, err := decodeClaims(out.WIT)
	if err != nil {
		return "", err
	}
	a.wit = out.WIT
	a.sub, _ = claims["sub"].(string)
	if exp, ok := claims["exp"].(float64); ok {
		a.expiry = time.Unix(int64(exp), 0)
	}
	return a.wit, nil
}

// Do sends a request carrying WIT + a fresh WPT bound to the target URI
// (and to the Txn-Token via tth when one is supplied).
func (a *Agent) Do(method, target, tp string, body []byte, contentType, txnToken string) (*http.Response, error) {
	witTok, err := a.WIT(tp)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	aud := u.Scheme + "://" + u.Host + u.EscapedPath() // target URI without query/fragment
	proof, err := wpt.Generate(wpt.GenerateOptions{TargetURI: aud, WIT: witTok, WorkloadKey: a.key.Private,
		TTL: 2 * time.Minute, TxnToken: txnToken})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set(HeaderWIT, witTok)
	req.Header.Set("Authorization", WPTScheme+" "+proof)
	if txnToken != "" {
		req.Header.Set(HeaderTxn, txnToken)
	}
	req.Header.Set("traceparent", ChildTraceparent(tp))
	return a.client.Do(req)
}

// PostJSON is Do for JSON bodies; it decodes the JSON response into out.
func (a *Agent) PostJSON(target, tp string, in any, txnToken string, out any) (int, error) {
	body, _ := json.Marshal(in)
	resp, err := a.Do(http.MethodPost, target, tp, body, "application/json", txnToken)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s response (%d): %s", target, resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, nil
}

// TxnToken asks the issuer's Transaction Token Service for a Txn-Token
// describing the business transaction this (entry) workload is starting.
func (a *Agent) TxnToken(tp, user, purpose string, details map[string]string) (string, error) {
	var out struct {
		TxnToken string `json:"txn_token"`
		Detail   string `json:"detail"`
	}
	status, err := a.PostJSON(a.IssuerURL+"/txn-token", tp,
		map[string]any{"subject": user, "purpose": purpose, "details": details}, "", &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || out.TxnToken == "" {
		return "", fmt.Errorf("txn-token request failed (%d): %s", status, out.Detail)
	}
	return out.TxnToken, nil
}

// Exchange performs RFC 8693 token exchange at the issuer: the workload
// authenticates with WIT + WPT and receives a short-lived, audience-restricted
// JWT that cloud federation endpoints (AWS AssumeRoleWithWebIdentity, GCP
// STS / Workload Identity Federation) understand. The WIT itself is never
// handed to a third party as a bearer token.
func (a *Agent) Exchange(tp, audience string) (string, error) {
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
		"audience":             {audience},
	}
	resp, err := a.Do(http.MethodPost, a.IssuerURL+"/token", tp, []byte(form.Encode()),
		"application/x-www-form-urlencoded", "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Detail      string `json:"detail"`
		Error       string `json:"error_description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", fmt.Errorf("token exchange failed (%d): %s%s", resp.StatusCode, out.Detail, out.Error)
	}
	return out.AccessToken, nil
}
