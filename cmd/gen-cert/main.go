package main

import (
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/wimse-identity-fabric/pkg/keys"
)

func main() {
	uri := flag.String("uri", "", "SPIFFE or WIMSE URI for the workload (required)")
	caCert := flag.String("ca-cert", "ca.crt", "Path to CA certificate PEM")
	caKey := flag.String("ca-key", "ca.key", "Path to CA private key PEM")
	certOut := flag.String("cert-out", "workload.crt", "Output path for workload certificate PEM")
	keyOut := flag.String("key-out", "workload.key", "Output path for workload private key PEM")
	dnsNames := flag.String("dns", "", "Comma-separated DNS SANs (e.g. localhost,myhost.example.com)")
	ipAddrs := flag.String("ip", "", "Comma-separated IP SANs (e.g. 127.0.0.1,10.0.0.1)")
	flag.Parse()

	if *uri == "" {
		log.Fatal("--uri is required")
	}

	ca, err := keys.LoadCABundle(*caCert, *caKey)
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}

	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		log.Fatalf("generate key pair: %v", err)
	}

	opts := &keys.CertOptions{}
	if *dnsNames != "" {
		opts.DNSNames = strings.Split(*dnsNames, ",")
	}
	if *ipAddrs != "" {
		for _, s := range strings.Split(*ipAddrs, ",") {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip == nil {
				log.Fatalf("invalid IP address: %q", s)
			}
			opts.IPAddresses = append(opts.IPAddresses, ip)
		}
	}

	wc, err := ca.IssueWorkloadCert(*uri, kp.Public, opts)
	if err != nil {
		log.Fatalf("issue workload cert: %v", err)
	}

	for _, p := range []string{*certOut, *keyOut} {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			log.Fatalf("create output directory: %v", err)
		}
	}

	if err := keys.SaveWorkloadCert(wc, *certOut); err != nil {
		log.Fatalf("save workload cert: %v", err)
	}
	if err := keys.SaveECPrivateKey(*keyOut, kp.Private); err != nil {
		log.Fatalf("save workload key: %v", err)
	}

	log.Printf("Workload cert generated: uri=%s cert=%s key=%s", *uri, *certOut, *keyOut)
}
