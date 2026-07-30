package wit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/golang-jwt/jwt/v5"
)

const issuerID = "https://idp.cloud-a.example"

func setup(t *testing.T) (*keys.ECKeyPair, *wit.Issuer, *wit.Validator, *keys.ECKeyPair) {
	t.Helper()
	idpKP, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	workloadKP, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	issuer := wit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	validator := wit.NewValidator(issuerID, idpKP.Public)
	return idpKP, issuer, validator, workloadKP
}

func defaultOpts(workloadKP *keys.ECKeyPair) wit.IssueOptions {
	return wit.IssueOptions{
		Subject:     "spiffe://cloud-a.example/workload-a",
		TrustDomain: "cloud-a.example",
		KeyID:       "wl-key-1",
		Audiences:   []string{"https://api.cloud-b.example"},
		WorkloadKey: workloadKP.Public,
	}
}

func TestWIT_HappyPath(t *testing.T) {
	_, issuer, validator, workloadKP := setup(t)
	token, err := issuer.Issue(defaultOpts(workloadKP))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	result, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Claims.Subject != "spiffe://cloud-a.example/workload-a" {
		t.Fatalf("unexpected subject: %q", result.Claims.Subject)
	}
	if result.WorkloadKey == nil {
		t.Fatal("expected non-nil workload key")
	}
}

func TestWIT_WrongKey(t *testing.T) {
	_, issuer, _, workloadKP := setup(t)
	token, _ := issuer.Issue(defaultOpts(workloadKP))

	// Create a second IdP key pair and try to validate with it
	otherKP, _ := keys.GenerateECKeyPair()
	wrongValidator := wit.NewValidator(issuerID, otherKP.Public)
	_, err := wrongValidator.Validate(token)
	if err == nil {
		t.Fatal("expected error for wrong validation key")
	}
}

func TestWIT_Expired(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()
	// Issue with -1s TTL (already expired)
	issuer := wit.NewIssuer(issuerID, idpKP.Private, -time.Second)
	token, err := issuer.Issue(wit.IssueOptions{
		Subject:     "spiffe://cloud-a.example/workload-a",
		WorkloadKey: workloadKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	validator := wit.NewValidator(issuerID, idpKP.Public)
	_, err = validator.Validate(token)
	if err == nil {
		t.Fatal("expected error for expired WIT")
	}
}

func TestWIT_IssuerMismatch(t *testing.T) {
	_, issuer, _, workloadKP := setup(t)
	token, _ := issuer.Issue(defaultOpts(workloadKP))

	// Validator expects a different issuer
	idpKP2, _ := keys.GenerateECKeyPair()
	wrongIssuerValidator := wit.NewValidator("https://other-idp.example", idpKP2.Public)
	_, err := wrongIssuerValidator.Validate(token)
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
}

func TestWIT_CnfKeyExtraction(t *testing.T) {
	_, issuer, validator, workloadKP := setup(t)
	token, _ := issuer.Issue(defaultOpts(workloadKP))
	result, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// The extracted workload key should match what we issued with
	if result.WorkloadKey.X.Cmp(workloadKP.Public.X) != 0 ||
		result.WorkloadKey.Y.Cmp(workloadKP.Public.Y) != 0 {
		t.Fatal("extracted workload key does not match issued key")
	}
}

func TestWIT_TypHeader(t *testing.T) {
	_, issuer, _, workloadKP := setup(t)
	token, _ := issuer.Issue(defaultOpts(workloadKP))

	// Parse without validation to inspect header
	p := jwt.NewParser()
	var claims wit.Claims
	t_, _, err := p.ParseUnverified(token, &claims)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	typ, _ := t_.Header["typ"].(string)
	if typ != "wit+jwt" {
		t.Fatalf("expected typ=wit+jwt, got %q", typ)
	}
}

func TestWIT_InputValidation_NoSubject(t *testing.T) {
	_, issuer, _, workloadKP := setup(t)
	_, err := issuer.Issue(wit.IssueOptions{WorkloadKey: workloadKP.Public})
	if err == nil {
		t.Fatal("expected error when subject is missing")
	}
}

func TestWIT_InputValidation_NoKey(t *testing.T) {
	_, issuer, _, _ := setup(t)
	_, err := issuer.Issue(wit.IssueOptions{Subject: "spiffe://cloud-a.example/x"})
	if err == nil {
		t.Fatal("expected error when workload key is missing")
	}
}

func TestWIT_TamperedToken(t *testing.T) {
	_, issuer, validator, workloadKP := setup(t)
	token, _ := issuer.Issue(defaultOpts(workloadKP))
	// Replace the signature section entirely to guarantee invalidity.
	parts := strings.SplitN(token, ".", 3)
	corrupted := parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, err := validator.Validate(corrupted)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}
