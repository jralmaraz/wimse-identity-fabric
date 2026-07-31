package idp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/internal/idp"
	"github.com/example/wimse-identity-fabric/pkg/federation"
	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/wit"
)

func newConfig(t *testing.T, allowed ...string) *idp.IdPConfig {
	t.Helper()
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("GenerateECKeyPair: %v", err)
	}
	return &idp.IdPConfig{
		TrustDomain:     "cloud-a.example",
		IssuerID:        "https://idp.cloud-a.example",
		SigningKey:       kp,
		TokenTTL:        time.Hour,
		AllowedSubjects: allowed,
	}
}

func workloadJWK(t *testing.T) (json.RawMessage, *keys.ECKeyPair) {
	t.Helper()
	kp, _ := keys.GenerateECKeyPair()
	jwk, err := keys.PublicKeyToJWK(kp.Public, "wl-key")
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	raw, _ := json.Marshal(jwk)
	return raw, kp
}

func doPost(t *testing.T, srv *httptest.Server, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := srv.Client().Post(srv.URL+"/wit/issue", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /wit/issue: %v", err)
	}
	return resp
}

func TestIssue_HappyPath(t *testing.T) {
	cfg := newConfig(t)
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	pubKeyRaw, _ := workloadJWK(t)
	resp := doPost(t, srv, map[string]interface{}{
		"subject":      "spiffe://cloud-a.example/workload-a",
		"trust_domain": "cloud-a.example",
		"public_key":   json.RawMessage(pubKeyRaw),
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	token := result["token"]
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Validate the issued token
	validator := wit.NewValidator(cfg.IssuerID, cfg.SigningKey.Public)
	vr, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("token validation: %v", err)
	}
	if vr.Claims.Subject != "spiffe://cloud-a.example/workload-a" {
		t.Fatalf("unexpected subject: %q", vr.Claims.Subject)
	}
}

func TestIssue_MissingSubject(t *testing.T) {
	cfg := newConfig(t)
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	pubKeyRaw, _ := workloadJWK(t)
	resp := doPost(t, srv, map[string]interface{}{
		"public_key": json.RawMessage(pubKeyRaw),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestIssue_InvalidPublicKey(t *testing.T) {
	cfg := newConfig(t)
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	resp := doPost(t, srv, map[string]interface{}{
		"subject":    "spiffe://cloud-a.example/x",
		"public_key": json.RawMessage(`{"kty":"EC","crv":"P-256","x":"bad","y":"bad","alg":"ES256"}`),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestIssue_SubjectNotAllowed(t *testing.T) {
	cfg := newConfig(t, "spiffe://cloud-a.example/allowed-only")
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	pubKeyRaw, _ := workloadJWK(t)
	resp := doPost(t, srv, map[string]interface{}{
		"subject":    "spiffe://cloud-a.example/not-allowed",
		"public_key": json.RawMessage(pubKeyRaw),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestJWKS_ReturnsIdPPublicKey(t *testing.T) {
	cfg := newConfig(t)
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET /.well-known/jwks.json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []keys.JWK `json:"keys"`
	}
	json.NewDecoder(resp.Body).Decode(&jwks)
	if len(jwks.Keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}
	if jwks.Keys[0].Alg != "ES256" {
		t.Fatalf("expected alg=ES256, got %q", jwks.Keys[0].Alg)
	}
}

func TestJWKS_ValidatesWIT(t *testing.T) {
	cfg := newConfig(t)
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	// Issue a token
	pubKeyRaw, _ := workloadJWK(t)
	resp := doPost(t, srv, map[string]interface{}{
		"subject":    "spiffe://cloud-a.example/svc",
		"public_key": json.RawMessage(pubKeyRaw),
	})
	defer resp.Body.Close()
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	token := result["token"]

	// Fetch JWKS
	jwksResp, err := srv.Client().Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET /.well-known/jwks.json: %v", err)
	}
	defer jwksResp.Body.Close()
	var jwksBody struct {
		Keys []keys.JWK `json:"keys"`
	}
	json.NewDecoder(jwksResp.Body).Decode(&jwksBody)

	pub, err := keys.JWKToPublicKey(&jwksBody.Keys[0])
	if err != nil {
		t.Fatalf("JWKToPublicKey: %v", err)
	}

	validator := wit.NewValidator(cfg.IssuerID, pub)
	if _, err := validator.Validate(token); err != nil {
		t.Fatalf("token validation via JWKS key: %v", err)
	}
}

func TestHealth(t *testing.T) {
	cfg := newConfig(t)
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestEntityConfig_ServedCorrectly(t *testing.T) {
	cfg := newConfig(t)
	cfg.OrganizationName = "Acme Corp Cloud A"
	cfg.AuthorityHints = []string{"https://trust-anchor.acme.example"}
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-federation")
	if err != nil {
		t.Fatalf("GET /.well-known/openid-federation: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/entity-statement+jwt" {
		t.Errorf("Content-Type: want %q got %q", "application/entity-statement+jwt", ct)
	}

	var body []byte
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if readErr != nil {
			break
		}
	}
	ecJWT := string(body)
	if ecJWT == "" {
		t.Fatal("expected non-empty entity configuration JWT")
	}

	// Parse without sig verification.
	ec, err := federation.ParseEntityConfiguration(ecJWT)
	if err != nil {
		t.Fatalf("ParseEntityConfiguration: %v", err)
	}
	if ec.Issuer != cfg.IssuerID {
		t.Errorf("iss: want %q got %q", cfg.IssuerID, ec.Issuer)
	}
	if len(ec.AuthorityHints) != 1 || ec.AuthorityHints[0] != "https://trust-anchor.acme.example" {
		t.Errorf("authority_hints: %v", ec.AuthorityHints)
	}

	// Verify signature with the IdP's own public key.
	verified, err := federation.VerifyEntityConfiguration(ecJWT, cfg.SigningKey.Public)
	if err != nil {
		t.Fatalf("VerifyEntityConfiguration: %v", err)
	}
	if verified.Issuer != cfg.IssuerID {
		t.Errorf("verified iss: want %q got %q", cfg.IssuerID, verified.Issuer)
	}
}

func TestFederationFetch_NotAnchor(t *testing.T) {
	cfg := newConfig(t) // no TrustAnchorSubjects
	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/federation/fetch?sub=https://idp.other.example")
	if err != nil {
		t.Fatalf("GET /federation/fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for non-anchor IdP, got %d", resp.StatusCode)
	}
}

func TestFederationFetch_WithSubject(t *testing.T) {
	cfg := newConfig(t)

	// Pre-build a subordinate statement.
	leafKP, _ := keys.GenerateECKeyPair()
	leafID := "https://idp.leaf.example"
	ssJWT, err := federation.BuildSubordinateStatement(
		cfg.IssuerID, leafID,
		leafKP.Public, "leaf-key",
		cfg.SigningKey.Private, "idp-key",
		time.Hour,
	)
	if err != nil {
		t.Fatalf("BuildSubordinateStatement: %v", err)
	}
	cfg.TrustAnchorSubjects = map[string]string{leafID: ssJWT}

	srv := httptest.NewServer(idp.NewRouter(cfg))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/federation/fetch?sub=" + leafID)
	if err != nil {
		t.Fatalf("GET /federation/fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body []byte
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if readErr != nil {
			break
		}
	}
	returned := string(body)
	if returned != ssJWT {
		t.Error("returned SS JWT does not match what was registered")
	}
}
