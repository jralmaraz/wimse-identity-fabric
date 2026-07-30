package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/example/wimse-identity-fabric/pkg/keys"
)

func main() {
	trustDomain := flag.String("trust-domain", "example.com", "Trust domain name embedded in CA subject")
	certOut := flag.String("cert-out", "ca.crt", "Output path for CA certificate PEM")
	keyOut := flag.String("key-out", "ca.key", "Output path for CA private key PEM")
	flag.Parse()

	for _, p := range []string{*certOut, *keyOut} {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			log.Fatalf("create output directory: %v", err)
		}
	}

	ca, err := keys.GenerateCA(*trustDomain)
	if err != nil {
		log.Fatalf("generate CA: %v", err)
	}

	if err := keys.SaveCABundle(ca, *certOut, *keyOut); err != nil {
		log.Fatalf("save CA: %v", err)
	}

	log.Printf("CA generated: cert=%s key=%s (trust-domain=%s)", *certOut, *keyOut, *trustDomain)
}
