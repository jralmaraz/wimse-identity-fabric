package workload_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/internal/workload"
	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/example/wimse-identity-fabric/pkg/wpt"
)

const (
	issuerID = "https://idp.cloud-a.example"
	subject  = "spiffe://cloud-a.example/workload-a"
)

// testSetup returns an IdP key pair, a workload key pair, a WIT, and validators.
func testSetup(t *testing.T) (idpKP, wlKP *keys.ECKeyPair, witToken string, wv *wit.Validator, pv *wpt.Validator) {
	t.Helper()
	idpKP, _ = keys.GenerateECKeyPair()
	wlKP, _ = keys.GenerateECKeyPair()

	issuer := wit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	witToken, err := issuer.Issue(wit.IssueOptions{
		Subject:     subject,
		WorkloadKey: wlKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue WIT: %v", err)
	}

	wv = wit.NewValidator(issuerID, idpKP.Public)
	pv = wpt.NewValidator()
	return idpKP, wlKP, witToken, wv, pv
}

// newTestServer starts a test HTTP server protected by WIMSE auth.
func newTestServer(t *testing.T, witValidator *wit.Validator, wptValidator *wpt.Validator) *httptest.Server {
	t.Helper()
	r := workload.NewProtectedRouter(witValidator, wptValidator)
	r.GET("/api/echo", workload.EchoHandler())
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func makeRequest(t *testing.T, srv *httptest.Server, witToken, wptToken string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/echo", nil)
	if witToken != "" {
		req.Header.Set(workload.HeaderWIT, witToken)
	}
	if wptToken != "" {
		req.Header.Set(workload.HeaderWPT, wptToken)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

func generateWPT(t *testing.T, targetURL, witToken string, wlKP *keys.ECKeyPair) string {
	t.Helper()
	wptToken, err := wpt.Generate(wpt.GenerateOptions{
		TargetURI:   targetURL,
		WIT:         witToken,
		WorkloadKey: wlKP.Private,
	})
	if err != nil {
		t.Fatalf("Generate WPT: %v", err)
	}
	return wptToken
}

func TestMiddleware_HappyPath(t *testing.T) {
	_, wlKP, witToken, wv, pv := testSetup(t)
	srv := newTestServer(t, wv, pv)

	wptToken := generateWPT(t, srv.URL+"/api/echo", witToken, wlKP)
	resp := makeRequest(t, srv, witToken, wptToken)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["caller"] != subject {
		t.Fatalf("unexpected caller: %q", body["caller"])
	}
}

func TestMiddleware_MissingWIT(t *testing.T) {
	_, wlKP, witToken, wv, pv := testSetup(t)
	srv := newTestServer(t, wv, pv)

	wptToken := generateWPT(t, srv.URL+"/api/echo", witToken, wlKP)
	resp := makeRequest(t, srv, "", wptToken) // no WIT
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestMiddleware_MissingWPT(t *testing.T) {
	_, _, witToken, wv, pv := testSetup(t)
	srv := newTestServer(t, wv, pv)

	resp := makeRequest(t, srv, witToken, "") // no WPT
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestMiddleware_InvalidWIT(t *testing.T) {
	_, wlKP, witToken, wv, pv := testSetup(t)
	srv := newTestServer(t, wv, pv)

	wptToken := generateWPT(t, srv.URL+"/api/echo", witToken, wlKP)
	// Replace the signature section entirely to guarantee invalidity.
	parts := strings.SplitN(witToken, ".", 3)
	tampered := parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	resp := makeRequest(t, srv, tampered, wptToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestMiddleware_InvalidWPT(t *testing.T) {
	_, wlKP, witToken, wv, pv := testSetup(t)
	srv := newTestServer(t, wv, pv)

	wptToken := generateWPT(t, srv.URL+"/api/echo", witToken, wlKP)
	// Replace the entire signature section (third JWT part) with zeros.
	parts := strings.SplitN(wptToken, ".", 3)
	tampered := parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	resp := makeRequest(t, srv, witToken, tampered)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestMiddleware_WPTAudienceMismatch(t *testing.T) {
	_, wlKP, witToken, wv, pv := testSetup(t)
	srv := newTestServer(t, wv, pv)

	// WPT aud = wrong URL
	wptToken := generateWPT(t, "https://other-service.example/api", witToken, wlKP)
	resp := makeRequest(t, srv, witToken, wptToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestMiddleware_ReplayAttack(t *testing.T) {
	_, wlKP, witToken, wv, pv := testSetup(t)
	srv := newTestServer(t, wv, pv)

	wptToken := generateWPT(t, srv.URL+"/api/echo", witToken, wlKP)

	// First request: should succeed
	resp1 := makeRequest(t, srv, witToken, wptToken)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", resp1.StatusCode)
	}

	// Second request with same WPT: should be rejected
	resp2 := makeRequest(t, srv, witToken, wptToken)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: expected 401, got %d", resp2.StatusCode)
	}
}

func TestClient_AttachesHeaders(t *testing.T) {
	_, wlKP, witToken, _, _ := testSetup(t)

	// Capture headers with a simple test handler
	var capturedWIT, capturedWPT string
	captureServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedWIT = r.Header.Get(workload.HeaderWIT)
		capturedWPT = r.Header.Get(workload.HeaderWPT)
		w.WriteHeader(http.StatusOK)
	}))
	defer captureServer.Close()

	c := workload.NewClient(nil, witToken, wlKP.Private)
	resp, err := c.Get(captureServer.URL + "/test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if capturedWIT == "" {
		t.Fatal("WIT header not set")
	}
	if capturedWPT == "" {
		t.Fatal("WPT header not set")
	}
}

func TestEndToEnd_WorkloadAtoB(t *testing.T) {
	// Set up shared CA
	ca, _ := keys.GenerateCA("cloud-a.example")

	// Workload A: caller
	wlAKP, _ := keys.GenerateECKeyPair()
	wlACert, _ := ca.IssueWorkloadCert("spiffe://cloud-a.example/workload-a", wlAKP.Public,
		&keys.CertOptions{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})

	// Workload B: callee
	wlBKP, _ := keys.GenerateECKeyPair()
	wlBCert, _ := ca.IssueWorkloadCert("spiffe://cloud-a.example/workload-b", wlBKP.Public,
		&keys.CertOptions{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})

	caPool := ca.CertPool()

	serverTLS, err := keys.NewServerTLSConfig(caPool, wlBCert, wlBKP.Private)
	if err != nil {
		t.Fatalf("server TLS: %v", err)
	}
	clientTLS, err := keys.NewClientTLSConfig(caPool, wlACert, wlAKP.Private)
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}

	// Issue WIT for Workload A
	idpKP, _ := keys.GenerateECKeyPair()
	issuer := wit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	witToken, _ := issuer.Issue(wit.IssueOptions{
		Subject:     subject,
		WorkloadKey: wlAKP.Public,
	})

	// Start Workload B server with mTLS
	witValidator := wit.NewValidator(issuerID, idpKP.Public)
	wptValidator := wpt.NewValidator()
	r := workload.NewProtectedRouter(witValidator, wptValidator)
	r.GET("/api/echo", workload.EchoHandler())

	bSrv := httptest.NewUnstartedServer(r)
	bSrv.TLS = serverTLS
	bSrv.StartTLS()
	defer bSrv.Close()

	// Create workload A client with mTLS
	client := workload.NewClient(clientTLS, witToken, wlAKP.Private)
	resp, err := client.Get(bSrv.URL + "/api/echo")
	if err != nil {
		t.Fatalf("A→B call: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["caller"] != subject {
		t.Fatalf("unexpected caller: %q", body["caller"])
	}
	if body["echo"] != "ok" {
		t.Fatalf("unexpected echo: %q", body["echo"])
	}
}
