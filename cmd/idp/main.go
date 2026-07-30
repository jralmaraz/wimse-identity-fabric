package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/example/wimse-identity-fabric/internal/idp"
	"github.com/example/wimse-identity-fabric/pkg/keys"
)

func main() {
	trustDomain := flag.String("trust-domain", envOr("IDP_TRUST_DOMAIN", "cloud-a.example"), "Trust domain for this IdP")
	issuerID := flag.String("issuer", envOr("IDP_ISSUER", ""), "Issuer ID embedded in WITs (default: https://idp.<trust-domain>)")
	port := flag.Int("port", 8080, "HTTP port to listen on")
	ttl := flag.Duration("ttl", time.Hour, "WIT token TTL")
	keyFile := flag.String("key-file", envOr("IDP_KEY_FILE", ""), "Path to persist IdP signing key PEM (generated on first run if absent)")
	flag.Parse()

	if *issuerID == "" {
		*issuerID = fmt.Sprintf("https://idp.%s", *trustDomain)
	}

	signingKey, err := loadOrGenerateKey(*keyFile)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}

	kp := &keys.ECKeyPair{Private: signingKey, Public: &signingKey.PublicKey}
	cfg := &idp.IdPConfig{
		TrustDomain: *trustDomain,
		IssuerID:    *issuerID,
		SigningKey:   kp,
		TokenTTL:    *ttl,
	}

	router := idp.NewRouter(cfg)
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("WIMSE IdP starting: trust_domain=%s issuer=%s addr=%s", cfg.TrustDomain, cfg.IssuerID, addr)

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// loadOrGenerateKey returns an EC private key from keyFile (loading if present,
// generating-and-saving if absent), or generates an ephemeral key when keyFile is empty.
func loadOrGenerateKey(keyFile string) (*ecdsa.PrivateKey, error) {
	if keyFile != "" {
		if _, err := os.Stat(keyFile); err == nil {
			k, err := keys.LoadECPrivateKey(keyFile)
			if err != nil {
				return nil, fmt.Errorf("load key from %s: %w", keyFile, err)
			}
			log.Printf("loaded signing key from %s", keyFile)
			return k, nil
		}
		kp, err := keys.GenerateECKeyPair()
		if err != nil {
			return nil, err
		}
		if err := keys.SaveECPrivateKey(keyFile, kp.Private); err != nil {
			return nil, fmt.Errorf("save key to %s: %w", keyFile, err)
		}
		log.Printf("generated and saved signing key to %s", keyFile)
		return kp.Private, nil
	}
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		return nil, err
	}
	log.Printf("using ephemeral signing key (restarts will rotate the key)")
	return kp.Private, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
