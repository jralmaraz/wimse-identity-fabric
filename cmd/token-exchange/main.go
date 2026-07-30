package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/example/wimse-identity-fabric/internal/exchange"
	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/wit"
)

func main() {
	sourceIdP := flag.String("source-idp", envOr("SOURCE_IDP_URL", "http://localhost:8080"), "Source IdP base URL")
	sourceIssuer := flag.String("source-issuer", envOr("SOURCE_IDP_ISSUER", ""), "Source IdP issuer ID (default: https://idp.<source-trust-domain>)")
	targetIdP := flag.String("target-idp", envOr("TARGET_IDP_URL", "http://localhost:8081"), "Target IdP base URL")
	targetIssuer := flag.String("target-issuer", envOr("TARGET_IDP_ISSUER", ""), "Target IdP issuer ID (default: https://idp.<target-trust-domain>)")
	port := flag.Int("port", 8090, "HTTP port to listen on")
	idpWait := flag.Duration("idp-wait", 2*time.Minute, "Max time to wait for IdP JWKS to become available")
	flag.Parse()

	if *sourceIssuer == "" {
		*sourceIssuer = *sourceIdP
	}
	if *targetIssuer == "" {
		*targetIssuer = *targetIdP
	}

	sourcePub, err := fetchJWKSWithRetry(*sourceIdP+"/.well-known/jwks.json", *idpWait)
	if err != nil {
		log.Fatalf("fetch source JWKS: %v", err)
	}

	// The target IdP issues the exchanged tokens — it needs a signing key.
	// For the PoC, fetch the target IdP's public key for reference and use a
	// freshly generated key to issue on behalf of the target trust domain.
	// In production, the target IdP would be a separate service; here we embed
	// a minimal issuer inside the exchange service.
	targetKP, err := keys.GenerateECKeyPair()
	if err != nil {
		log.Fatalf("generate target signing key: %v", err)
	}

	cfg := &exchange.ExchangeConfig{
		Policy: &exchange.TrustPolicy{
			AllowedIssuers: map[string]*ecdsa.PublicKey{
				*sourceIssuer: sourcePub,
			},
		},
		TargetIssuer: wit.NewIssuer(*targetIssuer, targetKP.Private, time.Hour),
		TokenTTL:     time.Hour,
	}

	r := exchange.NewRouter(cfg)
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Token Exchange Service starting on %s (source=%s → target=%s)", addr, *sourceIssuer, *targetIssuer)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("server: %v", err)
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
