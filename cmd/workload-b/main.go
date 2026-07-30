package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/example/wimse-identity-fabric/internal/workload"
	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/example/wimse-identity-fabric/pkg/wpt"
)

func main() {
	idpURL := flag.String("idp", envOr("IDP_URL", "http://localhost:8080"), "IdP base URL")
	issuerID := flag.String("issuer", envOr("IDP_ISSUER", ""), "Issuer ID (default: https://idp.<trust-domain>; set to match IdP --issuer)")
	port := flag.Int("port", 9001, "Plain HTTP port (used when no TLS cert is configured)")
	tlsPort := flag.Int("tls-port", 9443, "HTTPS port (used when --cert-file and --key-file are set)")
	caCert := flag.String("ca-cert", envOr("CA_CERT_FILE", ""), "CA certificate PEM (required for mTLS)")
	certFile := flag.String("cert-file", envOr("CERT_FILE", ""), "Workload certificate PEM (enables mTLS server)")
	keyFile := flag.String("key-file", envOr("KEY_FILE", ""), "Workload private key PEM (enables mTLS server)")
	idpWait := flag.Duration("idp-wait", 2*time.Minute, "Max time to wait for IdP JWKS to become available")
	flag.Parse()

	if *issuerID == "" {
		*issuerID = fmt.Sprintf("https://idp.%s", "cloud-a.example")
		log.Printf("--issuer not set, defaulting to %s (set --issuer to match the IdP's --issuer flag)", *issuerID)
	}

	idpPub, err := fetchJWKSWithRetry(*idpURL+"/.well-known/jwks.json", *idpWait)
	if err != nil {
		log.Fatalf("fetch JWKS: %v", err)
	}

	witValidator := wit.NewValidator(*issuerID, idpPub)
	wptValidator := wpt.NewValidator()

	r := workload.NewProtectedRouter(witValidator, wptValidator)
	r.GET("/api/echo", workload.EchoHandler())

	mtLS := *certFile != "" && *keyFile != ""

	if mtLS {
		if *caCert == "" {
			log.Fatal("--ca-cert is required when --cert-file and --key-file are set")
		}
		clientCA, err := keys.LoadCACertPool(*caCert)
		if err != nil {
			log.Fatalf("load CA cert pool: %v", err)
		}
		wc, err := keys.LoadWorkloadCert(*certFile)
		if err != nil {
			log.Fatalf("load workload cert: %v", err)
		}
		priv, err := keys.LoadECPrivateKey(*keyFile)
		if err != nil {
			log.Fatalf("load workload key: %v", err)
		}
		tlsCfg, err := keys.NewServerTLSConfig(clientCA, wc, priv)
		if err != nil {
			log.Fatalf("build TLS config: %v", err)
		}

		addr := fmt.Sprintf(":%d", *tlsPort)
		ln, err := tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			log.Fatalf("TLS listen: %v", err)
		}
		log.Printf("Workload B starting mTLS on %s (idp=%s issuer=%s)", addr, *idpURL, *issuerID)
		if err := http.Serve(ln, r); err != nil {
			log.Fatalf("serve: %v", err)
		}
	} else {
		addr := fmt.Sprintf(":%d", *port)
		log.Printf("Workload B starting plain HTTP on %s (idp=%s issuer=%s)", addr, *idpURL, *issuerID)
		if err := http.ListenAndServe(addr, r); err != nil {
			log.Fatalf("server: %v", err)
		}
	}
}

func fetchJWKSWithRetry(url string, maxWait time.Duration) (*ecdsa.PublicKey, error) {
	deadline := time.Now().Add(maxWait)
	for {
		pub, err := fetchJWKSPublicKey(url)
		if err == nil {
			return pub, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for JWKS at %s: %w", url, err)
		}
		log.Printf("waiting for JWKS at %s (%v)", url, err)
		time.Sleep(3 * time.Second)
	}
}

func fetchJWKSPublicKey(jwksURL string) (*ecdsa.PublicKey, error) {
	// Use a short timeout so the retry loop doesn't hang per attempt.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var jwksBody struct {
		Keys []keys.JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwksBody); err != nil || len(jwksBody.Keys) == 0 {
		return nil, fmt.Errorf("parse JWKS: %v", err)
	}
	return keys.JWKToPublicKey(&jwksBody.Keys[0])
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
