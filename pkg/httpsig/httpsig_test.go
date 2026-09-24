package httpsig_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/httpsig"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
)

const (
	targetURI = "https://svcb.example.com/api/orders"
	issuerID  = "https://idp.example.com"
)

func setupWIT(t *testing.T) (string, *keys.ECKeyPair) {
	t.Helper()
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()
	issuer := wit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	witToken, err := issuer.Issue(wit.IssueOptions{
		Subject:     "spiffe://example.com/svc/billing",
		WorkloadKey: workloadKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue WIT: %v", err)
	}
	return witToken, workloadKP
}

func signedRequest(t *testing.T, witToken string, workloadKP *keys.ECKeyPair) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, targetURI+"?item=1", nil)
	if err := httpsig.Sign(httpsig.SignOptions{
		Request:        r,
		WIT:            witToken,
		WorkloadKey:    workloadKP.Private,
		TargetAudience: targetURI,
	}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func TestHTTPSig_HappyPath(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := signedRequest(t, witToken, workloadKP)

	v := httpsig.NewVerifier()
	result, err := v.Verify(httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: workloadKP.Public,
		ExpectedAud:    targetURI,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Subject != "spiffe://example.com/svc/billing" {
		t.Errorf("unexpected subject %q", result.Subject)
	}
	if result.Aud != targetURI {
		t.Errorf("unexpected aud %q", result.Aud)
	}
	if result.Nonce == "" {
		t.Error("expected non-empty nonce")
	}
}

func TestHTTPSig_AudienceMismatch(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := signedRequest(t, witToken, workloadKP)

	v := httpsig.NewVerifier()
	_, err := v.Verify(httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: workloadKP.Public,
		ExpectedAud:    "https://other-service.example/api",
	})
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
}

func TestHTTPSig_TamperedSignature(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := signedRequest(t, witToken, workloadKP)

	// Flip one character in the base64 signature value.
	sig := r.Header.Get("Signature")
	if idx := strings.Index(sig, ":"); idx >= 0 {
		sigBytes := []byte(sig)
		// Find a character after "sig1=:" to tamper.
		start := idx + 1
		if start < len(sigBytes)-1 {
			if sigBytes[start] == 'A' {
				sigBytes[start] = 'B'
			} else {
				sigBytes[start] = 'A'
			}
		}
		r.Header.Set("Signature", string(sigBytes))
	}

	v := httpsig.NewVerifier()
	_, err := v.Verify(httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: workloadKP.Public,
		ExpectedAud:    targetURI,
	})
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestHTTPSig_ExpiredSignature(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := httptest.NewRequest(http.MethodGet, targetURI, nil)
	// Use negative TTL so the signature is already expired.
	err := httpsig.Sign(httpsig.SignOptions{
		Request:        r,
		WIT:            witToken,
		WorkloadKey:    workloadKP.Private,
		TargetAudience: targetURI,
		TTL:            -time.Second,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	v := httpsig.NewVerifier()
	_, err = v.Verify(httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: workloadKP.Public,
		ExpectedAud:    targetURI,
	})
	if err == nil {
		t.Fatal("expected error for expired signature")
	}
}

func TestHTTPSig_ReplayProtection(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := signedRequest(t, witToken, workloadKP)

	v := httpsig.NewVerifier()
	opts := httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: workloadKP.Public,
		ExpectedAud:    targetURI,
		CheckReplay:    true,
	}

	if _, err := v.Verify(opts); err != nil {
		t.Fatalf("first verification: %v", err)
	}
	_, err := v.Verify(opts)
	if err == nil {
		t.Fatal("expected replay error on second verification")
	}
}

func TestHTTPSig_WrongKey(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := signedRequest(t, witToken, workloadKP)

	otherKP, _ := keys.GenerateECKeyPair()
	v := httpsig.NewVerifier()
	_, err := v.Verify(httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: otherKP.Public,
		ExpectedAud:    targetURI,
	})
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestHTTPSig_MissingRequiredComponent(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := signedRequest(t, witToken, workloadKP)

	// Remove @query from covered components by stripping the @query part
	// from the Signature-Input header manually.
	si := r.Header.Get("Signature-Input")
	si = strings.ReplaceAll(si, `"@query" `, "")
	si = strings.ReplaceAll(si, ` "@query"`, "")
	r.Header.Set("Signature-Input", si)

	v := httpsig.NewVerifier()
	_, err := v.Verify(httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: workloadKP.Public,
		ExpectedAud:    targetURI,
	})
	if err == nil {
		t.Fatal("expected error for missing required component")
	}
}

func TestHTTPSig_ContentDigestCoveredWhenPresent(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := httptest.NewRequest(http.MethodPost, targetURI, strings.NewReader(`{"key":"val"}`))
	r.Header.Set("Content-Digest", "sha-256=:abc123==:")

	if err := httpsig.Sign(httpsig.SignOptions{
		Request:        r,
		WIT:            witToken,
		WorkloadKey:    workloadKP.Private,
		TargetAudience: targetURI,
	}); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	si := r.Header.Get("Signature-Input")
	if !strings.Contains(si, `"content-digest"`) {
		t.Error("expected content-digest to be included in Signature-Input when Content-Digest header present")
	}

	v := httpsig.NewVerifier()
	_, err := v.Verify(httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: workloadKP.Public,
		ExpectedAud:    targetURI,
	})
	if err != nil {
		t.Fatalf("Verify with content-digest: %v", err)
	}
}

func TestHTTPSig_InputValidation_NoWIT(t *testing.T) {
	_, workloadKP := setupWIT(t)
	r := httptest.NewRequest(http.MethodGet, targetURI, nil)
	err := httpsig.Sign(httpsig.SignOptions{
		Request:        r,
		WorkloadKey:    workloadKP.Private,
		TargetAudience: targetURI,
	})
	if err == nil {
		t.Fatal("expected error for missing WIT")
	}
}

func TestHTTPSig_InputValidation_NoAudience(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	r := httptest.NewRequest(http.MethodGet, targetURI, nil)
	err := httpsig.Sign(httpsig.SignOptions{
		Request:     r,
		WIT:         witToken,
		WorkloadKey: workloadKP.Private,
	})
	if err == nil {
		t.Fatal("expected error for missing target audience")
	}
}

func TestHTTPSig_MissingWITHeader(t *testing.T) {
	_, workloadKP := setupWIT(t)
	r := httptest.NewRequest(http.MethodGet, targetURI, nil)
	// Don't add WIT header — Verify should fail.
	v := httpsig.NewVerifier()
	_, err := v.Verify(httpsig.VerifyOptions{
		Request:        r,
		WorkloadPubKey: workloadKP.Public,
		ExpectedAud:    targetURI,
	})
	if err == nil {
		t.Fatal("expected error for missing WIT header")
	}
}
