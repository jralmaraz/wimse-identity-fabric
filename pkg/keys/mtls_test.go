package keys

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA("cloud-a.example")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if ca.Cert == nil || ca.Key == nil || len(ca.CertPEM) == 0 {
		t.Fatal("incomplete CA bundle")
	}
	if !ca.Cert.IsCA {
		t.Fatal("expected IsCA=true")
	}
}

func TestIssueWorkloadCert_SPIFFE(t *testing.T) {
	ca, _ := GenerateCA("cloud-a.example")
	kp, _ := GenerateECKeyPair()
	uri := "spiffe://cloud-a.example/workload-a"
	wc, err := ca.IssueWorkloadCert(uri, kp.Public, nil)
	if err != nil {
		t.Fatalf("IssueWorkloadCert: %v", err)
	}
	if len(wc.Cert.URIs) == 0 || wc.Cert.URIs[0].String() != uri {
		t.Fatalf("expected URI SAN %q, got %v", uri, wc.Cert.URIs)
	}
}

func TestIssueWorkloadCert_WIMSE(t *testing.T) {
	ca, _ := GenerateCA("cloud-b.example")
	kp, _ := GenerateECKeyPair()
	uri := "wimse://cloud-b.example/svc/orders"
	wc, err := ca.IssueWorkloadCert(uri, kp.Public, nil)
	if err != nil {
		t.Fatalf("IssueWorkloadCert: %v", err)
	}
	if len(wc.Cert.URIs) == 0 || wc.Cert.URIs[0].String() != uri {
		t.Fatalf("expected URI SAN %q, got %v", uri, wc.Cert.URIs)
	}
}

func TestMTLS_FullHandshake(t *testing.T) {
	ca, _ := GenerateCA("cloud-a.example")
	caPool := ca.CertPool()

	// Server cert
	serverKP, _ := GenerateECKeyPair()
	serverWC, _ := ca.IssueWorkloadCert("spiffe://cloud-a.example/server", serverKP.Public,
		&CertOptions{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})
	serverTLS, err := NewServerTLSConfig(caPool, serverWC, serverKP.Private)
	if err != nil {
		t.Fatalf("server TLS config: %v", err)
	}

	// Client cert
	clientKP, _ := GenerateECKeyPair()
	clientWC, _ := ca.IssueWorkloadCert("spiffe://cloud-a.example/client", clientKP.Public, nil)
	clientTLS, err := NewClientTLSConfig(caPool, clientWC, clientKP.Private)
	if err != nil {
		t.Fatalf("client TLS config: %v", err)
	}

	// Start test HTTPS server
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	// Override the server's TLS config URL with our custom one
	transport := &http.Transport{TLSClientConfig: clientTLS}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

func TestMTLS_WrongCA_Rejected(t *testing.T) {
	caA, _ := GenerateCA("cloud-a.example")
	caB, _ := GenerateCA("cloud-b.example")

	serverKP, _ := GenerateECKeyPair()
	serverWC, _ := caA.IssueWorkloadCert("spiffe://cloud-a.example/server", serverKP.Public,
		&CertOptions{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})
	serverTLS, _ := NewServerTLSConfig(caA.CertPool(), serverWC, serverKP.Private)

	// Client uses CA-B cert, server trusts only CA-A
	clientKP, _ := GenerateECKeyPair()
	clientWC, _ := caB.IssueWorkloadCert("spiffe://cloud-b.example/client", clientKP.Public, nil)
	clientTLS, _ := NewClientTLSConfig(caA.CertPool(), clientWC, clientKP.Private)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	transport := &http.Transport{TLSClientConfig: clientTLS}
	httpClient := &http.Client{Transport: transport}
	_, err := httpClient.Get(srv.URL)
	if err == nil {
		t.Fatal("expected TLS error for wrong CA, got none")
	}
}

func TestTLSCertificate(t *testing.T) {
	ca, _ := GenerateCA("test.example")
	kp, _ := GenerateECKeyPair()
	wc, _ := ca.IssueWorkloadCert("spiffe://test.example/svc", kp.Public, nil)
	tlsCert, err := TLSCertificate(wc, kp.Private)
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	if tlsCert.PrivateKey == nil {
		t.Fatal("expected non-nil private key")
	}
	_ = tls.Certificate(tlsCert)
}
