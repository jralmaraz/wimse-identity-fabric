package exchange_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/internal/exchange"
	"github.com/example/wimse-identity-fabric/internal/workload"
	"github.com/example/wimse-identity-fabric/pkg/federation"
	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/example/wimse-identity-fabric/pkg/wpt"
)

const (
	issuerA  = "https://idp.cloud-a.example"
	issuerB  = "https://idp.cloud-b.example"
	subjectA = "spiffe://cloud-a.example/svc/billing"
	subjectB = "spiffe://cloud-b.example/external/billing"
)

type testEnv struct {
	idpAKP *keys.ECKeyPair
	idpBKP *keys.ECKeyPair
	wlKP   *keys.ECKeyPair
	issA   *wit.Issuer
	issB   *wit.Issuer
	witA   string // valid WIT from IdP-A
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	idpAKP, _ := keys.GenerateECKeyPair()
	idpBKP, _ := keys.GenerateECKeyPair()
	wlKP, _ := keys.GenerateECKeyPair()

	issA := wit.NewIssuer(issuerA, idpAKP.Private, time.Hour)
	issB := wit.NewIssuer(issuerB, idpBKP.Private, time.Hour)

	witA, err := issA.Issue(wit.IssueOptions{
		Subject:     subjectA,
		WorkloadKey: wlKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue WIT-A: %v", err)
	}
	return &testEnv{
		idpAKP: idpAKP, idpBKP: idpBKP, wlKP: wlKP,
		issA: issA, issB: issB, witA: witA,
	}
}

func buildConfig(e *testEnv, subjectMap map[string]string, allowedSubs []string) *exchange.ExchangeConfig {
	policy := &exchange.TrustPolicy{
		AllowedIssuers:  map[string]*ecdsa.PublicKey{issuerA: e.idpAKP.Public},
		AllowedSubjects: allowedSubs,
		SubjectMap:      subjectMap,
	}
	return &exchange.ExchangeConfig{
		Policy:       policy,
		TargetIssuer: e.issB,
		TokenTTL:     time.Hour,
	}
}

func newSrv(t *testing.T, cfg *exchange.ExchangeConfig) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(exchange.NewRouter(cfg))
	t.Cleanup(srv.Close)
	return srv
}

func postExchange(t *testing.T, srv *httptest.Server, token string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": token})
	resp, err := srv.Client().Post(srv.URL+"/token/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /token/exchange: %v", err)
	}
	return resp
}

func TestExchange_HappyPath(t *testing.T) {
	e := setup(t)
	cfg := buildConfig(e, nil, nil)
	srv := newSrv(t, cfg)

	resp := postExchange(t, srv, e.witA)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if result.ExpiresIn <= 0 {
		t.Fatalf("expected positive expires_in, got %d", result.ExpiresIn)
	}

	// Validate the issued WIT-B with IdP-B's key and issuer
	validatorB := wit.NewValidator(issuerB, e.idpBKP.Public)
	vr, err := validatorB.Validate(result.Token)
	if err != nil {
		t.Fatalf("validate WIT-B: %v", err)
	}
	if vr.Claims.Subject != subjectA {
		t.Fatalf("subject: want %q, got %q", subjectA, vr.Claims.Subject)
	}
}

func TestExchange_SubjectRewrite(t *testing.T) {
	e := setup(t)
	subjectMap := map[string]string{subjectA: subjectB}
	cfg := buildConfig(e, subjectMap, nil)
	srv := newSrv(t, cfg)

	resp := postExchange(t, srv, e.witA)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	token := result["token"].(string)

	validatorB := wit.NewValidator(issuerB, e.idpBKP.Public)
	vr, err := validatorB.Validate(token)
	if err != nil {
		t.Fatalf("validate WIT-B: %v", err)
	}
	if vr.Claims.Subject != subjectB {
		t.Fatalf("expected rewritten subject %q, got %q", subjectB, vr.Claims.Subject)
	}
}

func TestExchange_UnknownIssuer(t *testing.T) {
	e := setup(t)
	// Issue with an IdP whose key is not registered in the policy
	unknownKP, _ := keys.GenerateECKeyPair()
	unknownIssuer := wit.NewIssuer("https://rogue-idp.example", unknownKP.Private, time.Hour)
	rogueWIT, _ := unknownIssuer.Issue(wit.IssueOptions{
		Subject:     subjectA,
		WorkloadKey: e.wlKP.Public,
	})

	cfg := buildConfig(e, nil, nil)
	srv := newSrv(t, cfg)

	resp := postExchange(t, srv, rogueWIT)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestExchange_InvalidWIT(t *testing.T) {
	e := setup(t)
	cfg := buildConfig(e, nil, nil)
	srv := newSrv(t, cfg)

	// Replace the signature part entirely so the token is definitely invalid.
	parts := strings.SplitN(e.witA, ".", 3)
	tampered := parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	resp := postExchange(t, srv, tampered)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestExchange_ExpiredWIT(t *testing.T) {
	idpAKP, _ := keys.GenerateECKeyPair()
	wlKP, _ := keys.GenerateECKeyPair()
	idpBKP, _ := keys.GenerateECKeyPair()

	expiredIssuer := wit.NewIssuer(issuerA, idpAKP.Private, -time.Second)
	expiredWIT, _ := expiredIssuer.Issue(wit.IssueOptions{
		Subject:     subjectA,
		WorkloadKey: wlKP.Public,
	})

	e := &testEnv{
		idpAKP: idpAKP,
		idpBKP: idpBKP,
		wlKP:   wlKP,
		issB:   wit.NewIssuer(issuerB, idpBKP.Private, time.Hour),
	}
	cfg := buildConfig(e, nil, nil)
	srv := newSrv(t, cfg)

	resp := postExchange(t, srv, expiredWIT)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestExchange_SubjectNotAllowed(t *testing.T) {
	e := setup(t)
	cfg := buildConfig(e, nil, []string{"spiffe://cloud-a.example/other-svc"})
	srv := newSrv(t, cfg)

	resp := postExchange(t, srv, e.witA)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// TestExchange_FederationTrust verifies that the exchange server accepts tokens
// from issuers not in AllowedIssuers when they are resolvable via OID-FED.
func TestExchange_FederationTrust(t *testing.T) {
	e := setup(t)

	// Trust Anchor key pair.
	anchorKP, _ := keys.GenerateECKeyPair()
	anchorID := "https://trust-anchor.corporate.example"

	// Build Entity Configuration for IdP-A.
	ecJWT, err := federation.BuildEntityConfiguration(
		issuerA, e.idpAKP.Private, "idpa-key", "Acme Cloud A",
		[]string{anchorID}, time.Hour,
	)
	if err != nil {
		t.Fatalf("BuildEntityConfiguration: %v", err)
	}
	// Build Subordinate Statement from anchor about IdP-A.
	ssJWT, err := federation.BuildSubordinateStatement(
		anchorID, issuerA,
		e.idpAKP.Public, "idpa-key",
		anchorKP.Private, "anchor-key",
		time.Hour,
	)
	if err != nil {
		t.Fatalf("BuildSubordinateStatement: %v", err)
	}

	// Exchange policy: no static AllowedIssuers — rely entirely on federation.
	resolver := federation.NewInMemoryResolver(map[string]*ecdsa.PublicKey{anchorID: anchorKP.Public})
	resolver.RegisterEntityConfig(issuerA, ecJWT)
	resolver.RegisterSubordinateStatement(issuerA, ssJWT)

	policy := &exchange.TrustPolicy{
		AllowedIssuers: map[string]*ecdsa.PublicKey{}, // empty — federation only
		Resolver:       resolver,
	}
	cfg := &exchange.ExchangeConfig{
		Policy:       policy,
		TargetIssuer: e.issB,
		TokenTTL:     time.Hour,
	}
	srv := newSrv(t, cfg)

	resp := postExchange(t, srv, e.witA)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	token, _ := result["token"].(string)
	if token == "" {
		t.Fatal("expected non-empty exchanged token")
	}

	// Token must validate against IdP-B.
	validatorB := wit.NewValidator(issuerB, e.idpBKP.Public)
	if _, err := validatorB.Validate(token); err != nil {
		t.Fatalf("validate federated WIT-B: %v", err)
	}
}

func TestEndToEnd_CrossDomain(t *testing.T) {
	e := setup(t)

	// Token exchange service: A→B
	cfg := buildConfig(e, map[string]string{subjectA: subjectB}, nil)
	exchangeSrv := newSrv(t, cfg)

	// Exchange WIT-A for WIT-B
	resp := postExchange(t, exchangeSrv, e.witA)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange: expected 200, got %d", resp.StatusCode)
	}
	var exResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&exResult)
	witB := exResult["token"].(string)

	// Set up Workload B protected server (trusts IdP-B)
	validatorB := wit.NewValidator(issuerB, e.idpBKP.Public)
	wptValidator := wpt.NewValidator()

	// mTLS CA for B's domain
	ca, _ := keys.GenerateCA("cloud-b.example")
	wlBKP, _ := keys.GenerateECKeyPair()
	wlBCert, _ := ca.IssueWorkloadCert("spiffe://cloud-b.example/workload-b", wlBKP.Public,
		&keys.CertOptions{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})

	wlAKP2, _ := keys.GenerateECKeyPair()
	wlACert, _ := ca.IssueWorkloadCert("spiffe://cloud-b.example/workload-a-ext", wlAKP2.Public,
		&keys.CertOptions{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})

	caPool := ca.CertPool()
	serverTLS, _ := keys.NewServerTLSConfig(caPool, wlBCert, wlBKP.Private)
	clientTLS, _ := keys.NewClientTLSConfig(caPool, wlACert, wlAKP2.Private)

	r := workload.NewProtectedRouter(validatorB, wptValidator)
	r.GET("/api/echo", workload.EchoHandler())

	bSrv := httptest.NewUnstartedServer(r)
	bSrv.TLS = serverTLS
	bSrv.StartTLS()
	defer bSrv.Close()

	// Workload A calls B using WIT-B (the exchanged token), still signed with wlKP
	client := workload.NewClient(clientTLS, witB, e.wlKP.Private)
	apiResp, err := client.Get(bSrv.URL + "/api/echo")
	if err != nil {
		t.Fatalf("A→B call: %v", err)
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", apiResp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(apiResp.Body).Decode(&body)
	if body["caller"] != subjectB {
		t.Fatalf("expected caller=%q, got %q", subjectB, body["caller"])
	}
}
