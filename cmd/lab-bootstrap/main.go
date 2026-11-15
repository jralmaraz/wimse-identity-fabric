// lab-bootstrap seeds the Floci AWS and GCP emulators for the local
// multi-cloud lab, then exits:
//
//	AWS: IAM roles orders-task / ledger-task (task roles used for attestation),
//	     OIDC provider for issuer-aws, IAM role ledger-data trusting it,
//	     DynamoDB table wimse-ledger
//	GCP: service account payments@<project>, KMS key ring/key for card data
//
// Every step is idempotent and retried while the emulators start.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/internal/lab"
	"github.com/jralmaraz/wimse-identity-fabric/internal/lab/cloud"
)

func main() {
	aws := cloud.AWSFromEnv()
	gcp := cloud.GCPFromEnv()
	issuerAWS := envOr("ISSUER_AWS_URL", "http://issuer-aws:8080")
	account := envOr("AWS_ACCOUNT_ID", "000000000000")
	oidcHost := strings.TrimPrefix(strings.TrimPrefix(issuerAWS, "https://"), "http://")

	ledgerTrust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"Federated":"arn:aws:iam::%s:oidc-provider/%s"},"Action":"sts:AssumeRoleWithWebIdentity",`+
		`"Condition":{"StringEquals":{"%s:aud":"sts.amazonaws.com","%s:sub":"%s"}}}]}`,
		account, oidcHost, oidcHost, oidcHost, envOr("LEDGER_ID", "spiffe://aws.wimse.local/ns/shop/sa/ledger"))
	taskTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`

	steps := []struct {
		dst, desc string
		fn        func() error
	}{
		{"floci-aws", "iam:CreateRole orders-task (attestation role, like an ECS task role)", func() error { return aws.CreateRole("orders-task", taskTrust) }},
		{"floci-aws", "iam:CreateRole ledger-task (attestation role, like an ECS task role)", func() error { return aws.CreateRole("ledger-task", taskTrust) }},
		{"floci-aws", "iam:CreateOpenIDConnectProvider for " + issuerAWS, func() error { return aws.CreateOIDCProvider(issuerAWS, "sts.amazonaws.com") }},
		{"floci-aws", "iam:CreateRole ledger-data (trusts issuer-aws OIDC, sub=ledger)", func() error { return aws.CreateRole("ledger-data", ledgerTrust) }},
		{"floci-aws", "dynamodb:CreateTable wimse-ledger", func() error { return aws.DynamoCreateTable(envOr("LEDGER_TABLE", "wimse-ledger"), "txn") }},
		{"floci-gcp", "iam serviceAccounts.create payments", func() error { return gcp.CreateServiceAccount("payments", "WIMSE lab payments") }},
		{"floci-gcp", "cloudkms keyRings/cryptoKeys.create wimse-lab/card-data", func() error {
			return gcp.EnsureCryptoKey(envOr("GCP_KMS_RING", "wimse-lab"), envOr("GCP_KMS_KEY", "card-data"))
		}},
	}

	failed := 0
	for _, s := range steps {
		err := retry(90*time.Second, s.fn)
		ev := lab.Event{TraceID: "bootstrap", Kind: "cloud", Src: "bootstrap", Dst: s.dst, OK: err == nil, Summary: s.desc}
		if err != nil {
			failed++
			ev.Summary += " FAILED: " + err.Error()
		}
		lab.Emit(ev)
	}
	time.Sleep(time.Second) // let the trace queue drain
	if failed > 0 {
		log.Printf("bootstrap finished with %d failed step(s); the WIMSE flow still works, cloud steps may not", failed)
		os.Exit(0) // non-fatal on purpose: emulator API coverage varies
	}
	log.Print("bootstrap complete")
}

func retry(max time.Duration, fn func() error) error {
	deadline := time.Now().Add(max)
	for {
		err := fn()
		if err == nil || time.Now().After(deadline) || !transient(err) {
			return err
		}
		time.Sleep(2 * time.Second)
	}
}

func transient(err error) bool {
	s := err.Error()
	return strings.Contains(s, "connection refused") || strings.Contains(s, "no such host") ||
		strings.Contains(s, "EOF") || strings.Contains(s, "timeout") || strings.Contains(s, "-> 5") || strings.Contains(s, " 50")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
