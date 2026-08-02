package spiffeclientauth_test

import (
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/spiffeclientauth"
	"github.com/example/wimse-identity-fabric/pkg/wit"
)

const (
	issuerID   = "https://idp.cloud-a.example"
	workloadID = "spiffe://cloud-a.example/svc/billing"
)

func setup(t *testing.T) (witToken string, auth *spiffeclientauth.Authenticator) {
	t.Helper()
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()

	issuer := wit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	token, err := issuer.Issue(wit.IssueOptions{
		Subject:     workloadID,
		WorkloadKey: workloadKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue WIT: %v", err)
	}

	validator := wit.NewValidator(issuerID, idpKP.Public)
	auth = spiffeclientauth.NewAuthenticator(issuerID, validator, time.Hour)
	return token, auth
}

func defaultReq(witToken string) spiffeclientauth.AuthRequest {
	return spiffeclientauth.AuthRequest{
		ClientAssertion:     witToken,
		ClientAssertionType: spiffeclientauth.ClientAssertionType,
		Scope:               "read:orders write:reports",
	}
}

func TestSPIFFEClientAuth_HappyPath(t *testing.T) {
	witToken, auth := setup(t)
	tok, err := auth.Authenticate(defaultReq(witToken))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if tok.Token == "" {
		t.Error("expected non-empty access_token")
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type: want Bearer got %q", tok.TokenType)
	}
	if tok.Sub != workloadID {
		t.Errorf("sub: want %q got %q", workloadID, tok.Sub)
	}
	if tok.ExpiresIn <= 0 {
		t.Error("expected positive expires_in")
	}
	if tok.Scope != "read:orders write:reports" {
		t.Errorf("scope: want %q got %q", "read:orders write:reports", tok.Scope)
	}
}

func TestSPIFFEClientAuth_TokensAreUnique(t *testing.T) {
	witToken, auth := setup(t)
	req := defaultReq(witToken)
	t1, _ := auth.Authenticate(req)
	t2, _ := auth.Authenticate(req)
	if t1.Token == t2.Token {
		t.Error("expected distinct access tokens on each call")
	}
}

func TestSPIFFEClientAuth_WrongAssertionType(t *testing.T) {
	witToken, auth := setup(t)
	req := defaultReq(witToken)
	req.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"
	if _, err := auth.Authenticate(req); err == nil {
		t.Error("expected error for wrong assertion type")
	}
}

func TestSPIFFEClientAuth_EmptyAssertion(t *testing.T) {
	_, auth := setup(t)
	req := spiffeclientauth.AuthRequest{
		ClientAssertionType: spiffeclientauth.ClientAssertionType,
	}
	if _, err := auth.Authenticate(req); err == nil {
		t.Error("expected error for empty client_assertion")
	}
}

func TestSPIFFEClientAuth_TamperedWIT(t *testing.T) {
	witToken, auth := setup(t)
	req := defaultReq(witToken + "tampered")
	if _, err := auth.Authenticate(req); err == nil {
		t.Error("expected error for tampered WIT")
	}
}

func TestSPIFFEClientAuth_ExpiredWIT(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()

	issuer := wit.NewIssuer(issuerID, idpKP.Private, -time.Second)
	token, _ := issuer.Issue(wit.IssueOptions{
		Subject:     workloadID,
		WorkloadKey: workloadKP.Public,
	})

	validator := wit.NewValidator(issuerID, idpKP.Public)
	auth := spiffeclientauth.NewAuthenticator(issuerID, validator, time.Hour)

	if _, err := auth.Authenticate(defaultReq(token)); err == nil {
		t.Error("expected error for expired WIT")
	}
}

func TestSPIFFEClientAuth_WrongIssuer(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()

	// WIT issued by idp-A, but validator is configured for idp-B
	issuer := wit.NewIssuer("https://idp-a.example", idpKP.Private, time.Hour)
	token, _ := issuer.Issue(wit.IssueOptions{
		Subject:     workloadID,
		WorkloadKey: workloadKP.Public,
	})

	validator := wit.NewValidator("https://idp-b.example", idpKP.Public)
	auth := spiffeclientauth.NewAuthenticator("https://idp-b.example", validator, time.Hour)

	if _, err := auth.Authenticate(defaultReq(token)); err == nil {
		t.Error("expected error for issuer mismatch")
	}
}

func TestSPIFFEClientAuth_NoScope(t *testing.T) {
	witToken, auth := setup(t)
	req := spiffeclientauth.AuthRequest{
		ClientAssertion:     witToken,
		ClientAssertionType: spiffeclientauth.ClientAssertionType,
	}
	tok, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if tok.Scope != "" {
		t.Errorf("expected empty scope, got %q", tok.Scope)
	}
}
