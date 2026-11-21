// lab-issuer is a trust domain's WIMSE issuer for the local multi-cloud lab.
//
// Compared to cmd/idp (which issues a WIT for any requested subject), it:
//   - issues WITs only after platform attestation (AWS STS, Docker, GCP IAM, join token)
//   - runs a Transaction Token Service for entry-point workloads (POST /txn-token)
//   - performs RFC 8693 token exchange (POST /token): a workload authenticated
//     with WIT + WPT gets a short-lived, audience-restricted JWT that cloud
//     federation endpoints (AWS AssumeRoleWithWebIdentity, GCP STS) accept
//   - publishes /.well-known/openid-configuration so clouds can trust it as an OIDC IdP
//
// Configuration (env):
//
//	TRUST_DOMAIN        aws.wimse.local
//	PUBLIC_URL          http://issuer-aws:8080   (issuer ID / iss, and base of every aud)
//	PORT                8080
//	REGISTRATIONS_FILE  /config/aws-registrations.json
//	ATTESTORS           aws-sts,docker            (see internal/lab/attest)
//	TRUST_DOMAINS       domains whose WITs this issuer accepts on /token and /txn-token
//	TXN_AUDIENCE        audience of issued Txn-Tokens (empty disables /txn-token)
//	EXCHANGE_AUDIENCES  comma list of audiences /token may mint for
//	WIT_TTL             1h
//	KEY_FILE            optional PEM path to persist the signing key
//	DOCKER_SOCKET, AWS_ENDPOINT_URL, GCP_ENDPOINT_URL ... for the attestors
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-identity-fabric/internal/lab"
	"github.com/jralmaraz/wimse-identity-fabric/internal/lab/attest"
	"github.com/jralmaraz/wimse-identity-fabric/internal/lab/cloud"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/txntoken"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wpt"
)

type issuer struct {
	name        string // e.g. issuer-aws (observer lane)
	trustDomain string
	publicURL   string
	key         *keys.ECKeyPair
	kid         string
	regs        []attest.Registration
	plan        attest.Plan
	wit         *wit.Issuer
	txn         *txntoken.Issuer
	txnAudience string
	exchangeAud []string
	attestJTIs  wpt.JTIStore
}

func main() {
	trustDomain := mustEnv("TRUST_DOMAIN")
	publicURL := strings.TrimRight(mustEnv("PUBLIC_URL"), "/")
	ttl, err := time.ParseDuration(envOr("WIT_TTL", "1h"))
	if err != nil {
		log.Fatalf("WIT_TTL: %v", err)
	}

	priv, err := loadOrGenerateKey(os.Getenv("KEY_FILE"))
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	regs, err := attest.LoadRegistrations(mustEnv("REGISTRATIONS_FILE"))
	if err != nil {
		log.Fatalf("registrations: %v", err)
	}
	for _, r := range regs {
		if d, err := lab.TrustDomainOf(r.ID); err != nil || d != trustDomain {
			log.Fatalf("registration %s: id %q must be a workload identifier in trust domain %s", r.Workload, r.ID, trustDomain)
		}
	}

	aws := cloud.AWSFromEnv()
	available := map[string]attest.Attestor{
		"join-token": attest.JoinToken{},
		"aws-sts":    attest.AWSSTS{AllowedHost: aws.Host(), HTTP: &http.Client{Timeout: 5 * time.Second}},
		"docker":     attest.Docker{Socket: envOr("DOCKER_SOCKET", "/var/run/docker.sock")},
		"gcp-iam":    attest.GCPIAM{GCP: cloud.GCPFromEnv()},
	}
	plan, err := attest.ParsePlan(envOr("ATTESTORS", "join-token"), available)
	if err != nil {
		log.Fatalf("ATTESTORS: %v", err)
	}

	bundle, err := lab.TrustBundleFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	if _, ok := bundle.Issuer(trustDomain); !ok {
		log.Fatalf("TRUST_DOMAINS must include this issuer's own domain %s", trustDomain)
	}

	kp := &keys.ECKeyPair{Private: priv, Public: &priv.PublicKey}
	is := &issuer{
		name:        envOr("SERVICE_NAME", "issuer-"+strings.SplitN(trustDomain, ".", 2)[0]),
		trustDomain: trustDomain,
		publicURL:   publicURL,
		key:         kp,
		kid:         "lab-" + trustDomain,
		regs:        regs,
		plan:        plan,
		wit:         wit.NewIssuer(publicURL, priv, ttl),
		txn:         txntoken.NewIssuer(publicURL, priv, 5*time.Minute),
		txnAudience: os.Getenv("TXN_AUDIENCE"),
		exchangeAud: splitList(os.Getenv("EXCHANGE_AUDIENCES")),
		attestJTIs:  wpt.NewInMemoryJTIStore(),
	}

	// Who may call the WIMSE-protected issuer endpoints.
	policy := map[string][]string{}
	for _, r := range regs {
		policy["/token"] = append(policy["/token"], r.ID)
		if r.EntryPoint {
			policy["/txn-token"] = append(policy["/txn-token"], r.ID)
		}
	}
	verifier := lab.NewVerifier(is.name, publicURL, bundle, policy)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		lab.WriteJSON(w, 200, map[string]string{"status": "ok", "trust_domain": trustDomain})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", is.jwks)
	mux.HandleFunc("GET /.well-known/openid-configuration", is.discovery)
	mux.HandleFunc("POST /attest", is.attest)
	mux.HandleFunc("POST /token", verifier.Handler(is.exchange))
	if is.txnAudience != "" {
		mux.HandleFunc("POST /txn-token", verifier.Handler(is.issueTxnToken))
	}

	addr := ":" + envOr("PORT", "8080")
	log.Printf("lab-issuer %s: trust_domain=%s issuer=%s attestors=%s registrations=%d txn=%v addr=%s",
		is.name, trustDomain, publicURL, os.Getenv("ATTESTORS"), len(regs), is.txnAudience != "", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (is *issuer) jwks(w http.ResponseWriter, _ *http.Request) {
	jwk, err := keys.PublicKeyToJWK(is.key.Public, is.kid)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	lab.WriteJSON(w, 200, map[string]any{"keys": []any{jwk}})
}

func (is *issuer) discovery(w http.ResponseWriter, _ *http.Request) {
	lab.WriteJSON(w, 200, map[string]any{
		"issuer":                                is.publicURL,
		"jwks_uri":                              is.publicURL + "/.well-known/jwks.json",
		"token_endpoint":                        is.publicURL + "/token",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
	})
}

// attest verifies the self-signed attestation request, runs the attestor plan
// for the claimed workload and issues a WIT bound to the request's key.
func (is *issuer) attest(w http.ResponseWriter, r *http.Request) {
	tp := r.Header.Get("traceparent")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	var checks []lab.Check
	claimed := "unknown"

	fail := func(status int, code, detail string) {
		checks = append(checks, lab.Check{Name: code, OK: false, Detail: detail})
		lab.Emit(lab.Event{TraceID: lab.TraceID(tp), Kind: "attest", Src: claimed, Dst: is.name, Method: "POST",
			Path: "/attest", Status: status, OK: false, Summary: "attestation REJECTED: " + detail, Checks: checks})
		lab.WriteProblem(w, &lab.Rejection{Status: status, Code: code, Detail: detail, Checks: checks})
	}

	// 1. The request is a JWS signed by the key to be certified (proof of possession).
	var workloadPub *ecdsa.PublicKey
	var jwkKid string
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt(),
		jwt.WithAudience(is.publicURL+"/attest"),
	).ParseWithClaims(strings.TrimSpace(string(body)), claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != lab.AttestTyp {
			return nil, fmt.Errorf("typ %q, want %s", typ, lab.AttestTyp)
		}
		raw, _ := json.Marshal(t.Header["jwk"])
		jwk, err := keys.JWKFromRawMessage(raw)
		if err != nil {
			return nil, err
		}
		pub, err := keys.JWKToPublicKey(jwk)
		if err != nil {
			return nil, err
		}
		workloadPub, jwkKid = pub, jwk.Kid
		return pub, nil
	})
	if name, ok := claims["workload"].(string); ok {
		claimed = name
	}
	if err != nil {
		fail(400, "invalid-attestation-request", "self-signed request invalid: "+err.Error())
		return
	}
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()
	if exp.Sub(iat.Time) > 2*time.Minute {
		fail(400, "invalid-attestation-request", "request lifetime longer than 2 minutes")
		return
	}
	jti, _ := claims["jti"].(string)
	if jti == "" || is.attestJTIs.Record(jti, exp.Time) != nil {
		fail(400, "replayed-attestation-request", "attestation request jti missing or replayed")
		return
	}
	checks = append(checks, lab.Check{Name: "Proof of possession", OK: true,
		Detail: "request signed by the ES256 key that will be bound into cnf.jwk"})

	// 2. Find the registration for the claimed workload.
	var reg *attest.Registration
	for i := range is.regs {
		if is.regs[i].Workload == claimed {
			reg = &is.regs[i]
		}
	}
	if reg == nil {
		fail(403, "unknown-workload", fmt.Sprintf("no registration for workload %q in %s", claimed, is.trustDomain))
		return
	}
	checks = append(checks, lab.Check{Name: "Registration", OK: true, Detail: claimed + " → " + reg.ID})

	// 3. Platform attestation.
	var ev []lab.Evidence
	raw, _ := json.Marshal(claims["evidence"])
	_ = json.Unmarshal(raw, &ev)
	remote, _, _ := net.SplitHostPort(r.RemoteAddr)
	used, aChecks, ok := is.plan.Run(r.Context(), attest.Request{RemoteIP: remote, Evidence: ev}, *reg)
	checks = append(checks, aChecks...)
	if !ok {
		fail(403, "attestation-failed", "no attestor group accepted the evidence")
		return
	}

	// 4. Issue the WIT (pkg/wit) binding the attested identity to the workload key.
	token, err := is.wit.Issue(wit.IssueOptions{Subject: reg.ID, TrustDomain: is.trustDomain, KeyID: jwkKid,
		WorkloadKey: workloadPub})
	if err != nil {
		fail(500, "issue-failed", err.Error())
		return
	}
	checks = append(checks, lab.Check{Name: "WIT issued", OK: true, Detail: "sub=" + reg.ID + ", typ=wit+jwt, cnf.jwk bound"})
	lab.Emit(lab.Event{TraceID: lab.TraceID(tp), Kind: "attest", Src: claimed, Dst: is.name, Method: "POST",
		Path: "/attest", Status: 200, OK: true, Summary: fmt.Sprintf("attested via %s → WIT for %s", used, reg.ID),
		Tokens: map[string]string{"WIT": token}, Checks: checks, Extra: map[string]any{"attestor": used}})
	lab.WriteJSON(w, 200, map[string]string{"wit": token, "sub": reg.ID})
}

// issueTxnToken: the entry-point workload starts a business transaction.
func (is *issuer) issueTxnToken(w http.ResponseWriter, r *http.Request, caller *lab.Caller) {
	var in struct {
		Subject string            `json:"subject"`
		Purpose string            `json:"purpose"`
		Details map[string]string `json:"details"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil || in.Subject == "" || in.Purpose == "" {
		lab.WriteJSON(w, 400, map[string]string{"detail": "subject and purpose are required"})
		return
	}
	remote, _, _ := net.SplitHostPort(r.RemoteAddr)
	tok, err := is.txn.Issue(txntoken.IssueOptions{
		Subject:   in.Subject,
		Audiences: []string{is.txnAudience},
		ReqCtx:    &txntoken.RequestContext{ReqIP: remote, ReqWL: caller.ID},
		AzDetails: []txntoken.AuthorizationDetail{{Type: in.Purpose, Claims: in.Details}},
	})
	if err != nil {
		lab.WriteJSON(w, 500, map[string]string{"detail": err.Error()})
		return
	}
	lab.Emit(lab.Event{TraceID: lab.TraceID(caller.Traceprnt), Kind: "txn-token", Src: is.name, Dst: lab.ShortName(caller.ID),
		OK: true, Summary: fmt.Sprintf("Txn-Token for user %s (%s), req_wl=%s", in.Subject, in.Purpose, lab.ShortName(caller.ID)),
		Tokens: map[string]string{"Txn-Token": tok}})
	lab.WriteJSON(w, 200, map[string]string{"txn_token": tok})
}

// exchange implements RFC 8693 for WIT+WPT-authenticated workloads.
func (is *issuer) exchange(w http.ResponseWriter, r *http.Request, caller *lab.Caller) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", err.Error())
		return
	}
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		oauthError(w, "unsupported_grant_type", "only token-exchange is supported")
		return
	}
	aud := r.PostForm.Get("audience")
	if !contains(is.exchangeAud, aud) {
		oauthError(w, "invalid_target", fmt.Sprintf("audience %q is not allowed (allowed: %v)", aud, is.exchangeAud))
		return
	}
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": is.publicURL, "sub": caller.ID, "aud": aud, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "jti": fmt.Sprintf("%x", now.UnixNano()),
	})
	t.Header["typ"] = "JWT"
	t.Header["kid"] = is.kid
	tok, err := t.SignedString(is.key.Private)
	if err != nil {
		oauthError(w, "server_error", err.Error())
		return
	}
	lab.Emit(lab.Event{TraceID: lab.TraceID(caller.Traceprnt), Kind: "token-exchange", Src: is.name, Dst: lab.ShortName(caller.ID),
		OK: true, Summary: "RFC 8693: WIT+WPT → 5-min bearer JWT for " + aud,
		Tokens: map[string]string{"Exchanged JWT": tok}})
	lab.WriteJSON(w, 200, map[string]any{
		"access_token":      tok,
		"issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_type":        "N_A",
		"expires_in":        300,
	})
}

func oauthError(w http.ResponseWriter, code, desc string) {
	lab.WriteJSON(w, 400, map[string]string{"error": code, "error_description": desc})
}

func loadOrGenerateKey(path string) (*ecdsa.PrivateKey, error) {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return keys.LoadECPrivateKey(path)
		}
	}
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		return nil, err
	}
	if path != "" {
		if err := keys.SaveECPrivateKey(path, kp.Private); err != nil {
			return nil, err
		}
	}
	return kp.Private, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
