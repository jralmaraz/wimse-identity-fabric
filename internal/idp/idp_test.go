package idp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/internal/idp"
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
