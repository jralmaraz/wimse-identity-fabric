package identitychaining_test

import (
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/identitychaining"
	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/golang-jwt/jwt/v5"
)

const (
	domainAIssuer    = "https://as.cloud-a.example"
	domainBEndpoint  = "https://as.cloud-b.example/token"
	workloadSPIFFEID = "spiffe://cloud-a.example/svc/billing"
)

// issueWIT creates a WIT for domain A signed by idpKP.
func issueWIT(t *testing.T, idpKP, workloadKP *keys.ECKeyPair) string {
	t.Helper()
	issuer := wit.NewIssuer(domainAIssuer, idpKP.Private, time.Hour)
	tok, err := issuer.Issue(wit.IssueOptions{
		Subject:     workloadSPIFFEID,
		WorkloadKey: workloadKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue WIT: %v", err)
	}
	return tok
}

func setup(t *testing.T) (witToken string, grantIssuer *identitychaining.GrantIssuer, domainAKP *keys.ECKeyPair) {
	t.Helper()
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()
	domainAKP, _ = keys.GenerateECKeyPair()

	witToken = issueWIT(t, idpKP, workloadKP)
	validator := wit.NewValidator(domainAIssuer, idpKP.Public)
	grantIssuer = identitychaining.NewGrantIssuer(domainAIssuer, domainAKP.Private, validator, 5*time.Minute)
	return
}

func TestIdentityChaining_HappyPath(t *testing.T) {
	witToken, grantIssuer, domainAKP := setup(t)

	grant, err := grantIssuer.Issue(witToken, domainBEndpoint)
	if err != nil {
		t.Fatalf("Issue grant: %v", err)
	}

	validator := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	claims, err := validator.Validate(grant, domainBEndpoint)
	if err != nil {
		t.Fatalf("Validate grant: %v", err)
	}
	if claims.Subject != workloadSPIFFEID {
		t.Errorf("sub: want %q got %q", workloadSPIFFEID, claims.Subject)
	}
	if claims.Issuer != domainAIssuer {
		t.Errorf("iss: want %q got %q", domainAIssuer, claims.Issuer)
	}
}

func TestIdentityChaining_TypHeader(t *testing.T) {
	witToken, grantIssuer, _ := setup(t)
	grant, _ := grantIssuer.Issue(witToken, domainBEndpoint)

	p := jwt.NewParser()
	var c identitychaining.GrantClaims
	tok, _, err := p.ParseUnverified(grant, &c)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	typ, _ := tok.Header["typ"].(string)
	if typ != "jwt-authz-grant" {
		t.Errorf("typ: want jwt-authz-grant got %q", typ)
	}
}

func TestIdentityChaining_AudienceMismatch(t *testing.T) {
	witToken, grantIssuer, domainAKP := setup(t)
	grant, _ := grantIssuer.Issue(witToken, domainBEndpoint)

	validator := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	_, err := validator.Validate(grant, "https://different-as.example/token")
	if err == nil {
		t.Error("expected error for audience mismatch")
	}
}

func TestIdentityChaining_WrongSigningKey(t *testing.T) {
	witToken, grantIssuer, _ := setup(t)
	grant, _ := grantIssuer.Issue(witToken, domainBEndpoint)

	otherKP, _ := keys.GenerateECKeyPair()
	validator := identitychaining.NewGrantValidator(domainAIssuer, otherKP.Public)
	if _, err := validator.Validate(grant, domainBEndpoint); err == nil {
		t.Error("expected error for wrong signing key")
	}
}

func TestIdentityChaining_ExpiredGrant(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()
	domainAKP, _ := keys.GenerateECKeyPair()

	witToken := issueWIT(t, idpKP, workloadKP)
	validator := wit.NewValidator(domainAIssuer, idpKP.Public)
	grantIssuer := identitychaining.NewGrantIssuer(domainAIssuer, domainAKP.Private, validator, -time.Second)

	grant, _ := grantIssuer.Issue(witToken, domainBEndpoint)

	gv := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	if _, err := gv.Validate(grant, domainBEndpoint); err == nil {
		t.Error("expected error for expired grant")
	}
}

func TestIdentityChaining_IssuerMismatch(t *testing.T) {
	witToken, grantIssuer, domainAKP := setup(t)
	grant, _ := grantIssuer.Issue(witToken, domainBEndpoint)

	// Validator configured for wrong issuer
	validator := identitychaining.NewGrantValidator("https://imposter.example", domainAKP.Public)
	if _, err := validator.Validate(grant, domainBEndpoint); err == nil {
		t.Error("expected error for issuer mismatch")
	}
}

func TestIdentityChaining_InvalidWIT(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	domainAKP, _ := keys.GenerateECKeyPair()

	validator := wit.NewValidator(domainAIssuer, idpKP.Public)
	grantIssuer := identitychaining.NewGrantIssuer(domainAIssuer, domainAKP.Private, validator, 5*time.Minute)

	// Tampered WIT — validator should reject it
	if _, err := grantIssuer.Issue("not.a.valid.wit", domainBEndpoint); err == nil {
		t.Error("expected error for invalid WIT")
	}
}

func TestIdentityChaining_MissingSubjectToken(t *testing.T) {
	_, grantIssuer, _ := setup(t)
	if _, err := grantIssuer.Issue("", domainBEndpoint); err == nil {
		t.Error("expected error for empty subject token")
	}
}

func TestIdentityChaining_MissingTargetAudience(t *testing.T) {
	witToken, grantIssuer, _ := setup(t)
	if _, err := grantIssuer.Issue(witToken, ""); err == nil {
		t.Error("expected error for empty target audience")
	}
}

func TestIdentityChaining_EndToEnd(t *testing.T) {
	// Full cross-domain flow:
	// 1. Domain A issues WIT to workload
	// 2. Workload presents WIT to domain A's GrantIssuer → gets JWT grant
	// 3. Workload presents grant to domain B's GrantValidator → domain B extracts SPIFFE ID
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()
	domainAKP, _ := keys.GenerateECKeyPair()

	// Step 1: issue WIT
	witIssuer := wit.NewIssuer(domainAIssuer, idpKP.Private, time.Hour)
	witToken, _ := witIssuer.Issue(wit.IssueOptions{
		Subject:     workloadSPIFFEID,
		WorkloadKey: workloadKP.Public,
	})

	// Step 2: exchange WIT for JWT grant at domain A's AS
	witValidator := wit.NewValidator(domainAIssuer, idpKP.Public)
	grantIssuer := identitychaining.NewGrantIssuer(domainAIssuer, domainAKP.Private, witValidator, 5*time.Minute)
	grant, err := grantIssuer.Issue(witToken, domainBEndpoint)
	if err != nil {
		t.Fatalf("Issue grant: %v", err)
	}

	// Step 3: domain B validates the grant
	grantValidator := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	claims, err := grantValidator.Validate(grant, domainBEndpoint)
	if err != nil {
		t.Fatalf("Validate grant: %v", err)
	}

	if claims.Subject != workloadSPIFFEID {
		t.Errorf("expected SPIFFE ID %q, got %q", workloadSPIFFEID, claims.Subject)
	}
}
