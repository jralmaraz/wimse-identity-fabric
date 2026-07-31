//go:build js && wasm

// Package main is the WebAssembly entry point for the WIMSE Identity Fabric browser demo.
// It exposes Go functions to JavaScript via syscall/js so that index.html can drive
// a live, interactive walkthrough of the WIMSE token lifecycle.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"syscall/js"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/sdwit"
	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/example/wimse-identity-fabric/pkg/wpt"
)

// ---------- global demo state ----------

var (
	idpKP     *keys.ECKeyPair
	idpIssuer *wit.Issuer
	sdIssuer  *sdwit.Issuer

	workloadKP *keys.ECKeyPair
	witToken   string
	wptToken   string
	wptVal     *wpt.Validator
	sdToken    string

	usedJTIs = map[string]bool{}
)

const (
	issuerID    = "https://idp.cloud-a.example"
	subjectURI  = "spiffe://cloud-a.example/workload-a"
	trustDomain = "cloud-a.example"
	targetURI   = "https://api.cloud-b.example/data"
)

// ---------- helpers ----------

func ok(data interface{}) js.Value {
	b, err := json.Marshal(map[string]interface{}{"ok": true, "data": data})
	if err != nil {
		return js.ValueOf(fmt.Sprintf(`{"ok":false,"error":"%s"}`, err.Error()))
	}
	return js.ValueOf(string(b))
}

func fail(msg string) js.Value {
	b, _ := json.Marshal(map[string]interface{}{"ok": false, "error": msg})
	return js.ValueOf(string(b))
}

func jwtParts(token string) map[string]interface{} {
	parts := splitDot(token, 3)
	if len(parts) < 3 {
		return nil
	}
	header := decodeB64JSON(parts[0])
	payload := decodeB64JSON(parts[1])
	return map[string]interface{}{
		"header":    header,
		"payload":   payload,
		"signature": parts[2],
		"raw":       map[string]string{"header": parts[0], "payload": parts[1], "signature": parts[2]},
	}
}

func splitDot(s string, n int) []string {
	out := make([]string, 0, n)
	start := 0
	count := 0
	for i := 0; i < len(s) && count < n-1; i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
			count++
		}
	}
	out = append(out, s[start:])
	return out
}

func decodeB64JSON(s string) interface{} {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	return v
}

// ---------- WASM-exported functions ----------

// setup initialises the IdP key pair and issuers. Must be called first.
func setup(_ js.Value, _ []js.Value) interface{} {
	var err error
	idpKP, err = keys.GenerateECKeyPair()
	if err != nil {
		return fail("generate IdP key: " + err.Error())
	}
	workloadKP, err = keys.GenerateECKeyPair()
	if err != nil {
		return fail("generate workload key: " + err.Error())
	}

	idpIssuer = wit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	sdIssuer = sdwit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	wptVal = wpt.NewValidator()

	jwk, err := keys.PublicKeyToJWK(idpKP.Public, "idp-key-1")
	if err != nil {
		return fail("serialize IdP JWK: " + err.Error())
	}

	wkJWK, err := keys.PublicKeyToJWK(workloadKP.Public, "wl-key-1")
	if err != nil {
		return fail("serialize workload JWK: " + err.Error())
	}

	return ok(map[string]interface{}{
		"message":      "IdP and workload keys generated",
		"issuerID":     issuerID,
		"subject":      subjectURI,
		"trustDomain":  trustDomain,
		"idpJWK":       jwk,
		"workloadJWK":  wkJWK,
	})
}

// issueWIT issues a Workload Identity Token.
func issueWIT(_ js.Value, _ []js.Value) interface{} {
	if idpIssuer == nil {
		return fail("call setup() first")
	}
	var err error
	witToken, err = idpIssuer.Issue(wit.IssueOptions{
		Subject:     subjectURI,
		TrustDomain: trustDomain,
		WorkloadKey: workloadKP.Public,
	})
	if err != nil {
		return fail("issue WIT: " + err.Error())
	}

	parts := jwtParts(witToken)
	return ok(map[string]interface{}{
		"token":  witToken,
		"parts":  parts,
		"issuer": issuerID,
		"sub":    subjectURI,
		"td":     trustDomain,
	})
}

// generateWPT generates a Workload Proof Token bound to witToken.
func generateWPT(_ js.Value, _ []js.Value) interface{} {
	if witToken == "" {
		return fail("call issueWIT() first")
	}
	var err error
	wptToken, err = wpt.Generate(wpt.GenerateOptions{
		TargetURI:   targetURI,
		WIT:         witToken,
		WorkloadKey: workloadKP.Private,
		TTL:         5 * time.Minute,
	})
	if err != nil {
		return fail("generate WPT: " + err.Error())
	}

	h := sha256.Sum256([]byte(witToken))
	wth := base64.RawURLEncoding.EncodeToString(h[:])

	parts := jwtParts(wptToken)
	return ok(map[string]interface{}{
		"token":     wptToken,
		"parts":     parts,
		"wthDigest": wth,
		"targetURI": targetURI,
	})
}

// validateRequest simulates a verifier validating an incoming WIT+WPT request.
func validateRequest(_ js.Value, _ []js.Value) interface{} {
	if wptToken == "" {
		return fail("call generateWPT() first")
	}

	// Step 1: validate WIT
	witV := wit.NewValidator(issuerID, idpKP.Public)
	witResult, err := witV.Validate(witToken)
	if err != nil {
		return fail("WIT validation failed: " + err.Error())
	}

	// Step 2: validate WPT
	_, err = wptVal.Validate(wpt.ValidateOptions{
		WPTString:         wptToken,
		WITString:         witToken,
		WorkloadPublicKey: witResult.WorkloadKey,
		RequestURI:        targetURI,
		CheckReplay:       true,
	})
	if err != nil {
		return fail("WPT validation failed: " + err.Error())
	}

	return ok(map[string]interface{}{
		"steps": []string{
			"Parse Workload-Identity-Token header",
			"Verify WIT ES256 signature (IdP public key)",
			"Check WIT expiry, nbf, iat",
			"Verify WIT iss == expected issuer",
			"Extract workload public key from cnf.jwk",
			"Verify WPT ES256 signature (workload key)",
			"Confirm WPT aud == request URI (exact match)",
			"Verify WPT wth == SHA-256(WIT)",
			"Check WPT jti not replayed",
		},
		"subject":     witResult.Claims.Subject,
		"trustDomain": witResult.Claims.TrustDomain,
		"targetURI":   targetURI,
	})
}

// replayAttack attempts to replay the same WPT (should fail).
func replayAttack(_ js.Value, _ []js.Value) interface{} {
	if wptToken == "" {
		return fail("call generateWPT() first")
	}

	witV := wit.NewValidator(issuerID, idpKP.Public)
	witResult, err := witV.Validate(witToken)
	if err != nil {
		return fail("WIT validation: " + err.Error())
	}

	// First use (should succeed).
	_, firstErr := wptVal.Validate(wpt.ValidateOptions{
		WPTString:         wptToken,
		WITString:         witToken,
		WorkloadPublicKey: witResult.WorkloadKey,
		RequestURI:        targetURI,
		CheckReplay:       true,
	})

	// Second use (should fail — jti replayed).
	_, secondErr := wptVal.Validate(wpt.ValidateOptions{
		WPTString:         wptToken,
		WITString:         witToken,
		WorkloadPublicKey: witResult.WorkloadKey,
		RequestURI:        targetURI,
		CheckReplay:       true,
	})

	firstOK := firstErr == nil
	secondFailed := secondErr != nil

	msg := ""
	if secondErr != nil {
		msg = secondErr.Error()
	}

	return ok(map[string]interface{}{
		"firstAttemptAllowed":  firstOK,
		"secondAttemptBlocked": secondFailed,
		"replayError":          msg,
		"explanation":          "The jti (JWT ID) in the WPT is tracked server-side. A replay of the same token is rejected even if the signature is valid.",
	})
}

// issueSDWIT issues an SD-JWT WIT with sub, trust_domain, and roles selectively disclosable.
func issueSDWIT(_ js.Value, _ []js.Value) interface{} {
	if sdIssuer == nil {
		return fail("call setup() first")
	}
	var err error
	sdToken, err = sdIssuer.Issue(sdwit.IssueOptions{
		Subject:     subjectURI,
		TrustDomain: trustDomain,
		Roles:       []string{"billing", "reader"},
		WorkloadKey: workloadKP.Public,
		Selective: sdwit.SelectiveClaims{
			Sub:         true,
			TrustDomain: true,
			Roles:       true,
		},
	})
	if err != nil {
		return fail("issue SD-WIT: " + err.Error())
	}

	revealed, err := sdwit.RevealedClaims(sdToken)
	if err != nil {
		return fail("RevealedClaims: " + err.Error())
	}

	splitToken := splitSDJWT(sdToken)

	return ok(map[string]interface{}{
		"token":          sdToken,
		"jwtPart":        splitToken[0],
		"disclosures":    splitToken[1:],
		"revealedClaims": revealed,
		"explanation":    "The JWT payload contains only _sd hashes. Actual claim values are in separate Disclosure objects appended after ~",
	})
}

// presentSDWIT creates a limited presentation revealing only selected claims.
func presentSDWIT(_ js.Value, args []js.Value) interface{} {
	if sdToken == "" {
		return fail("call issueSDWIT() first")
	}

	reveal := []string{"sub"}
	if len(args) > 0 && args[0].Type() == js.TypeString {
		var claims []string
		if err := json.Unmarshal([]byte(args[0].String()), &claims); err == nil {
			reveal = claims
		}
	}

	limited, err := sdwit.Present(sdToken, reveal)
	if err != nil {
		return fail("Present: " + err.Error())
	}

	revealedFull, _ := sdwit.RevealedClaims(sdToken)
	revealedLimited, _ := sdwit.RevealedClaims(limited)

	splitFull := splitSDJWT(sdToken)
	splitLimited := splitSDJWT(limited)

	return ok(map[string]interface{}{
		"fullToken":          sdToken,
		"limitedToken":       limited,
		"fullDisclosures":    splitFull[1:],
		"limitedDisclosures": splitLimited[1:],
		"revealedFull":       revealedFull,
		"revealedLimited":    revealedLimited,
		"hiddenClaims":       difference(revealedFull, revealedLimited),
	})
}

// validateSDWIT validates a selective presentation and returns the visible claims.
func validateSDWIT(_ js.Value, args []js.Value) interface{} {
	if sdToken == "" {
		return fail("call issueSDWIT() first")
	}

	tokenToValidate := sdToken
	if len(args) > 0 && args[0].Type() == js.TypeString && args[0].String() != "" {
		tokenToValidate = args[0].String()
	}

	v := sdwit.NewValidator(issuerID, idpKP.Public)
	claims, err := v.Validate(tokenToValidate)
	if err != nil {
		return fail("Validate SD-WIT: " + err.Error())
	}

	return ok(map[string]interface{}{
		"issuer":      claims.Issuer,
		"subject":     claims.Subject,
		"trustDomain": claims.TrustDomain,
		"roles":       claims.Roles,
		"hasKey":      claims.WorkloadKey != nil,
		"expiry":      claims.Expiry,
	})
}

// checkAuthorization evaluates whether the current workload (identified by its WIT) may
// perform action on resource, using a hardcoded demo ABAC/RBAC policy table.
// This demonstrates how WIT claims (sub, trust_domain) drive fine-grained access control.
func checkAuthorization(_ js.Value, args []js.Value) interface{} {
	if witToken == "" {
		return fail("call issueWIT() first")
	}

	resource := "api:billing-data"
	action := "read"
	if len(args) >= 1 && args[0].Type() == js.TypeString {
		resource = args[0].String()
	}
	if len(args) >= 2 && args[1].Type() == js.TypeString {
		action = args[1].String()
	}

	// Validate the WIT to get claims — WASM does the real crypto.
	witV := wit.NewValidator(issuerID, idpKP.Public)
	witResult, err := witV.Validate(witToken)
	if err != nil {
		return fail("WIT validation: " + err.Error())
	}

	subject := witResult.Claims.Subject
	td := witResult.Claims.TrustDomain

	type rule struct {
		subjectPrefix string
		resource      string
		action        string
		allow         bool
		description   string
	}

	// Demo policy — in production this would be an OPA/Cedar/OpenFGA policy.
	policy := []rule{
		{"spiffe://cloud-a.example/", "api:billing-data", "read", true, "cloud-a workloads may read billing data"},
		{"spiffe://cloud-a.example/", "api:billing-data", "write", false, "write access requires explicit admin grant"},
		{"spiffe://cloud-a.example/admin", "api:billing-data", "write", true, "admin workload has explicit write grant"},
		{"spiffe://cloud-a.example/", "api:payment", "execute", false, "payment API requires separate approval process"},
		{"spiffe://cloud-b.example/", "api:billing-data", "read", false, "cross-domain reads blocked — use token exchange"},
	}

	policyRows := make([]map[string]interface{}, len(policy))
	for i, r := range policy {
		policyRows[i] = map[string]interface{}{
			"subjectPattern": r.subjectPrefix + "*",
			"resource":       r.resource,
			"action":         r.action,
			"allow":          r.allow,
			"description":    r.description,
		}
	}

	allowed := false
	matchIdx := -1
	matchDesc := "no matching rule — default DENY"
	for i, r := range policy {
		if strings.HasPrefix(subject, r.subjectPrefix) && r.resource == resource && r.action == action {
			allowed = r.allow
			matchIdx = i
			matchDesc = r.description
			break
		}
	}

	return ok(map[string]interface{}{
		"allowed":     allowed,
		"subject":     subject,
		"trustDomain": td,
		"resource":    resource,
		"action":      action,
		"matchedRule": matchIdx,
		"matchDesc":   matchDesc,
		"policy":      policyRows,
	})
}

// generateMTLSCert generates a demo CA and workload X.509 certificate with
// a SPIFFE URI Subject Alternative Name, demonstrating the mTLS identity layer.
func generateMTLSCert(_ js.Value, _ []js.Value) interface{} {
	if workloadKP == nil {
		return fail("call setup() first")
	}

	ca, err := keys.GenerateCA(trustDomain)
	if err != nil {
		return fail("generate CA: " + err.Error())
	}

	cert, err := ca.IssueWorkloadCert(subjectURI, workloadKP.Public, &keys.CertOptions{
		DNSNames: []string{"workload-a.cloud-a.example"},
	})
	if err != nil {
		return fail("issue cert: " + err.Error())
	}

	c := cert.Cert
	var uris []string
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}

	// Compute a fingerprint of the cert for display.
	h := sha256.Sum256(cert.CertPEM)
	fp := base64.RawURLEncoding.EncodeToString(h[:16]) // first 128 bits

	return ok(map[string]interface{}{
		"subject":    subjectURI,
		"spiffeURIs": uris,
		"dnsNames":   c.DNSNames,
		"issuer":     ca.Cert.Subject.CommonName,
		"notBefore":  c.NotBefore.Format(time.RFC3339),
		"notAfter":   c.NotAfter.Format(time.RFC3339),
		"keyType":    "EC P-256",
		"sigAlg":     "ECDSA-SHA256",
		"serial":     c.SerialNumber.String(),
		"fingerprint": fp,
		"pem":        string(cert.CertPEM),
		"caPEM":      string(ca.CertPEM),
		"tlsVersion": "TLS 1.3",
		"explanation": "SPIFFE URI SAN binds this certificate to the workload's cryptographic identity. The cert is used for mTLS mutual authentication at the transport layer.",
	})
}

// ---------- internal helpers ----------

func splitSDJWT(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '~' {
			part := s[start:i]
			if part != "" || len(parts) == 0 {
				parts = append(parts, part)
			}
			start = i + 1
		}
	}
	return parts
}

func difference(all, subset []string) []string {
	set := map[string]bool{}
	for _, s := range subset {
		set[s] = true
	}
	var diff []string
	for _, s := range all {
		if !set[s] {
			diff = append(diff, s)
		}
	}
	return diff
}

// ---------- main ----------

func main() {
	js.Global().Set("wimse", js.ValueOf(map[string]interface{}{
		"setup":               js.FuncOf(setup),
		"issueWIT":            js.FuncOf(issueWIT),
		"generateWPT":         js.FuncOf(generateWPT),
		"validateRequest":     js.FuncOf(validateRequest),
		"replayAttack":        js.FuncOf(replayAttack),
		"issueSDWIT":          js.FuncOf(issueSDWIT),
		"presentSDWIT":        js.FuncOf(presentSDWIT),
		"validateSDWIT":       js.FuncOf(validateSDWIT),
		"checkAuthorization":  js.FuncOf(checkAuthorization),
		"generateMTLSCert":    js.FuncOf(generateMTLSCert),
	}))

	// Block forever — WASM modules must not exit.
	<-make(chan struct{})
}
