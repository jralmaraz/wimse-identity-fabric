package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/example/wimse-identity-fabric/internal/workload"
	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/gin-gonic/gin"
)

func main() {
	idpURL := flag.String("idp", envOr("IDP_URL", "http://localhost:8080"), "IdP base URL")
	targetURL := flag.String("target", envOr("TARGET_URL", "http://localhost:9001"), "Workload B base URL")
	port := flag.Int("port", 9000, "HTTP port to listen on")
	subject := flag.String("subject", envOr("WORKLOAD_SUBJECT", "spiffe://cloud-a.example/workload-a"), "Workload A's identity")
	caCert := flag.String("ca-cert", envOr("CA_CERT_FILE", ""), "CA certificate PEM for mTLS (enables mTLS client)")
	certFile := flag.String("cert-file", envOr("CERT_FILE", ""), "Workload certificate PEM for mTLS")
	keyFile := flag.String("key-file", envOr("KEY_FILE", ""), "Workload private key PEM for mTLS")
	idpWait := flag.Duration("idp-wait", 2*time.Minute, "Max time to wait for IdP to become available")
	flag.Parse()

	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		log.Fatalf("generate key pair: %v", err)
	}

	witToken, err := obtainWITWithRetry(*idpURL, *subject, kp, *idpWait)
	if err != nil {
		log.Fatalf("obtain WIT: %v", err)
	}
	log.Printf("WIT obtained for subject %s", *subject)

	var tlsCfg *tls.Config
	if *caCert != "" && *certFile != "" && *keyFile != "" {
		serverCA, err := keys.LoadCACertPool(*caCert)
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
		tlsCfg, err = keys.NewClientTLSConfig(serverCA, wc, priv)
		if err != nil {
			log.Fatalf("build TLS config: %v", err)
		}
		log.Printf("mTLS client configured (ca=%s cert=%s)", *caCert, *certFile)
	}

	client := workload.NewClient(tlsCfg, witToken, kp.Private)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/call-b", func(c *gin.Context) {
		resp, err := client.Get(*targetURL + "/api/echo")
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		c.JSON(resp.StatusCode, result)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Workload A starting on %s (target=%s)", addr, *targetURL)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func obtainWITWithRetry(idpURL, subject string, kp *keys.ECKeyPair, maxWait time.Duration) (string, error) {
	deadline := time.Now().Add(maxWait)
	for {
		token, err := obtainWIT(idpURL, subject, kp)
		if err == nil {
			return token, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timeout waiting for IdP at %s: %w", idpURL, err)
		}
		log.Printf("waiting for IdP at %s (%v)", idpURL, err)
		time.Sleep(3 * time.Second)
	}
}

func obtainWIT(idpURL, subject string, kp *keys.ECKeyPair) (string, error) {
	jwk, err := keys.PublicKeyToJWK(kp.Public, "wl-key")
	if err != nil {
		return "", err
	}
	jwkRaw, _ := json.Marshal(jwk)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"subject":    subject,
		"public_key": json.RawMessage(jwkRaw),
	})

	resp, err := http.Post(idpURL+"/wit/issue", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("POST /wit/issue: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if result.Token == "" {
		return "", fmt.Errorf("IdP returned empty token (status %d)", resp.StatusCode)
	}
	return result.Token, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
