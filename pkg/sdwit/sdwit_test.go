package sdwit_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/sdwit"
	"github.com/golang-jwt/jwt/v5"
)

const (
	issuerID    = "https://idp.cloud-a.example"
	subjectURI  = "spiffe://cloud-a.example/workload-a"
	trustDomain = "cloud-a.example"
)

func setup(t *testing.T) (idpKP *keys.ECKeyPair, workloadKP *keys.ECKeyPair, issuer *sdwit.Issuer) {
	t.Helper()
	idpKP, _ = keys.GenerateECKeyPair()
	workloadKP, _ = keys.GenerateECKeyPair()
	issuer = sdwit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	return
}

func defaultOpts(workloadKP *keys.ECKeyPair) sdwit.IssueOptions {
	return sdwit.IssueOptions{
		Subject:     subjectURI,
		TrustDomain: trustDomain,
		Roles:       []string{"caller", "billing"},
		WorkloadKey: workloadKP.Public,
	}
}

// ── Happy path ────────────────────────────────────────────────────────────────

func TestSDWIT_HappyPath_NoSelectiveDisclosure(t *testing.T) {
	idpKP, workloadKP, issuer := setup(t)
	token, err := issuer.Issue(defaultOpts(workloadKP))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.Contains(token, "~") {
		t.Fatal("SD-JWT must contain ~ separator")
	}

	v := sdwit.NewValidator(issuerID, idpKP.Public)
	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != subjectURI {
		t.Errorf("Subject: want %s, got %s", subjectURI, claims.Subject)
	}
	if claims.TrustDomain != trustDomain {
		t.Errorf("TrustDomain: want %s, got %s", trustDomain, claims.TrustDomain)
	}
	if len(claims.Roles) != 2 {
		t.Errorf("Roles: want 2, got %v", claims.Roles)
	}
	if claims.WorkloadKey == nil {
		t.Fatal("WorkloadKey must not be nil")
	}
}

// ── Selective disclosure ───────────────────────────────────────────────────────

func TestSDWIT_SelectivePresentation_SubOnly(t *testing.T) {
	idpKP, workloadKP, issuer := setup(t)

	// Issue with sub, trust_domain, roles all selectively disclosable.
	opts := defaultOpts(workloadKP)
	opts.Selective = sdwit.SelectiveClaims{Sub: true, TrustDomain: true, Roles: true}
	fullToken, err := issuer.Issue(opts)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Confirm the full token reveals all three.
	revealed, err := sdwit.RevealedClaims(fullToken)
	if err != nil {
		t.Fatalf("RevealedClaims: %v", err)
	}
	if len(revealed) != 3 {
		t.Errorf("full token should have 3 disclosures, got %v", revealed)
	}

	// Present only sub.
	limited, err := sdwit.Present(fullToken, []string{"sub"})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	limitedRevealed, _ := sdwit.RevealedClaims(limited)
	if len(limitedRevealed) != 1 || limitedRevealed[0] != "sub" {
		t.Errorf("limited presentation should reveal only sub, got %v", limitedRevealed)
	}

	// Validate the limited presentation — verifier sees sub but NOT roles/trust_domain.
	v := sdwit.NewValidator(issuerID, idpKP.Public)
	claims, err := v.Validate(limited)
	if err != nil {
		t.Fatalf("Validate limited: %v", err)
	}
	if claims.Subject != subjectURI {
		t.Errorf("Subject: want %s, got %s", subjectURI, claims.Subject)
	}
	if claims.TrustDomain != "" {
		t.Errorf("TrustDomain should be empty (not disclosed), got %q", claims.TrustDomain)
	}
	if claims.Roles != nil {
		t.Errorf("Roles should be nil (not disclosed), got %v", claims.Roles)
	}
	if claims.WorkloadKey == nil {
		t.Fatal("WorkloadKey must always be present")
	}
}

func TestSDWIT_SelectivePresentation_AllRevealed(t *testing.T) {
	idpKP, workloadKP, issuer := setup(t)
	opts := defaultOpts(workloadKP)
	opts.Selective = sdwit.SelectiveClaims{Sub: true, TrustDomain: true, Roles: true}
	fullToken, _ := issuer.Issue(opts)

	v := sdwit.NewValidator(issuerID, idpKP.Public)
	claims, err := v.Validate(fullToken)
	if err != nil {
		t.Fatalf("Validate full: %v", err)
	}
	if claims.Subject == "" {
		t.Error("Subject should be present in full presentation")
	}
	if claims.TrustDomain == "" {
		t.Error("TrustDomain should be present in full presentation")
	}
	if len(claims.Roles) == 0 {
		t.Error("Roles should be present in full presentation")
	}
}

func TestSDWIT_PartialSelective_RolesOnly(t *testing.T) {
	idpKP, workloadKP, issuer := setup(t)

	// sub and trust_domain in JWT payload; only roles selective.
	opts := defaultOpts(workloadKP)
	opts.Selective = sdwit.SelectiveClaims{Roles: true}
	token, _ := issuer.Issue(opts)

	v := sdwit.NewValidator(issuerID, idpKP.Public)
	full, err := v.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// sub and trust_domain always visible
	if full.Subject == "" {
		t.Error("Subject should always be visible when not selective")
	}
	if full.TrustDomain == "" {
		t.Error("TrustDomain should always be visible when not selective")
	}
	// roles from disclosure
	if len(full.Roles) == 0 {
		t.Error("Roles should be visible in full presentation")
	}

	// Present without roles — verifier loses roles but keeps sub/trust_domain.
	noRoles, _ := sdwit.Present(token, []string{})
	limited, err := v.Validate(noRoles)
	if err != nil {
		t.Fatalf("Validate noRoles: %v", err)
	}
	if limited.Subject == "" {
		t.Error("Subject still visible (non-selective)")
	}
	if limited.Roles != nil {
		t.Errorf("Roles should be hidden, got %v", limited.Roles)
	}
}

// ── Token type header ──────────────────────────────────────────────────────────

func TestSDWIT_TypHeader(t *testing.T) {
	_, workloadKP, issuer := setup(t)
	token, _ := issuer.Issue(defaultOpts(workloadKP))

	signedJWT := strings.SplitN(token, "~", 2)[0]
	p := jwt.NewParser()
	var mc jwt.MapClaims
	tok, _, err := p.ParseUnverified(signedJWT, &mc)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if tok.Header["typ"] != sdwit.WITTyp {
		t.Errorf("typ: want %s, got %v", sdwit.WITTyp, tok.Header["typ"])
	}
}

// ── Expiry ────────────────────────────────────────────────────────────────────

func TestSDWIT_Expired(t *testing.T) {
	idpKP, workloadKP, _ := setup(t)
	expiredIssuer := sdwit.NewIssuer(issuerID, idpKP.Private, -time.Second)
	token, err := expiredIssuer.Issue(defaultOpts(workloadKP))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	v := sdwit.NewValidator(issuerID, idpKP.Public)
	_, err = v.Validate(token)
	if err == nil {
		t.Fatal("expected error for expired SD-WIT")
	}
}

// ── Signature integrity ────────────────────────────────────────────────────────

func TestSDWIT_WrongKey(t *testing.T) {
	_, workloadKP, issuer := setup(t)
	token, _ := issuer.Issue(defaultOpts(workloadKP))

	otherKP, _ := keys.GenerateECKeyPair()
	v := sdwit.NewValidator(issuerID, otherKP.Public)
	_, err := v.Validate(token)
	if err == nil {
		t.Fatal("expected error for wrong IdP key")
	}
}

func TestSDWIT_TamperedJWT(t *testing.T) {
	idpKP, workloadKP, issuer := setup(t)
	token, _ := issuer.Issue(defaultOpts(workloadKP))

	// Replace entire JWT signature with zeros.
	tildeIdx := strings.Index(token, "~")
	signedJWT := token[:tildeIdx]
	rest := token[tildeIdx:]

	parts := strings.SplitN(signedJWT, ".", 3)
	tampered := parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + rest

	v := sdwit.NewValidator(issuerID, idpKP.Public)
	_, err := v.Validate(tampered)
	if err == nil {
		t.Fatal("expected error for tampered JWT signature")
	}
}

// ── Disclosure integrity ───────────────────────────────────────────────────────

func TestSDWIT_TamperedDisclosure(t *testing.T) {
	idpKP, workloadKP, issuer := setup(t)
	opts := defaultOpts(workloadKP)
	opts.Selective = sdwit.SelectiveClaims{Sub: true}
	token, _ := issuer.Issue(opts)

	// Corrupt the first disclosure character.
	parts := strings.Split(token, "~")
	if len(parts) < 2 {
		t.Fatal("expected at least one disclosure")
	}
	disc := parts[1]
	if len(disc) > 0 {
		// flip first base64 character
		corrupted := string(rune(disc[0]+1)) + disc[1:]
		parts[1] = corrupted
	}
	tampered := strings.Join(parts, "~")

	v := sdwit.NewValidator(issuerID, idpKP.Public)
	_, err := v.Validate(tampered)
	if err == nil {
		t.Fatal("expected error for tampered disclosure")
	}
}

// ── WPT wth binding compatibility ────────────────────────────────────────────

func TestSDWIT_WthBinding(t *testing.T) {
	// Demonstrates that the existing WPT wth mechanism (sha256 of the token string)
	// works unchanged with an SD-JWT WIT — the WPT hashes the full SD-JWT string
	// (including all disclosures), binding the per-request proof to the full credential.
	_, workloadKP, issuer := setup(t)
	opts := defaultOpts(workloadKP)
	opts.Selective = sdwit.SelectiveClaims{Sub: true, Roles: true}
	sdWIT, err := issuer.Issue(opts)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Reproduce the wth computation from pkg/wpt/helpers.go.
	h := sha256.Sum256([]byte(sdWIT))
	wth := base64.RawURLEncoding.EncodeToString(h[:])
	if wth == "" {
		t.Fatal("wth must not be empty")
	}

	// A presentation with only sub has a different hash — the WPT is bound to
	// the full token (with all disclosures), not to any particular presentation.
	limited, _ := sdwit.Present(sdWIT, []string{"sub"})
	h2 := sha256.Sum256([]byte(limited))
	wth2 := base64.RawURLEncoding.EncodeToString(h2[:])
	if wth == wth2 {
		t.Error("wth of full token and limited presentation must differ")
	}
}

// ── End-to-end ────────────────────────────────────────────────────────────────

func TestSDWIT_EndToEnd(t *testing.T) {
	// Full SPICE-style selective disclosure flow:
	//   Issuer issues full SD-WIT → Holder presents subset → Verifier sees limited claims.
	idpKP, workloadKP, issuer := setup(t)

	// Issuer: issue credential with all three claims selectively disclosable.
	fullToken, err := issuer.Issue(sdwit.IssueOptions{
		Subject:     subjectURI,
		TrustDomain: trustDomain,
		Roles:       []string{"admin", "billing"},
		WorkloadKey: workloadKP.Public,
		Selective:   sdwit.SelectiveClaims{Sub: true, TrustDomain: true, Roles: true},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Holder: present only subject to a lower-trust service.
	presentation, err := sdwit.Present(fullToken, []string{"sub"})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	// Verifier: validate presentation.
	v := sdwit.NewValidator(issuerID, idpKP.Public)
	claims, err := v.Validate(presentation)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// sub is revealed.
	if claims.Subject != subjectURI {
		t.Errorf("Subject: want %s, got %s", subjectURI, claims.Subject)
	}
	// trust_domain and roles are hidden — verifier cannot learn them.
	if claims.TrustDomain != "" {
		t.Errorf("TrustDomain should be hidden from verifier, got %q", claims.TrustDomain)
	}
	if claims.Roles != nil {
		t.Errorf("Roles should be hidden from verifier, got %v", claims.Roles)
	}
	// cnf.jwk is always visible — WPT validation still works.
	if claims.WorkloadKey == nil {
		t.Fatal("WorkloadKey must always be present for WPT validation")
	}
}
