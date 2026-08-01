package wpt_test

import (
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/keys"
	"github.com/example/wimse-identity-fabric/pkg/wit"
	"github.com/example/wimse-identity-fabric/pkg/wpt"
	"github.com/golang-jwt/jwt/v5"
)

const (
	targetURI = "https://api.cloud-b.example/orders"
	issuerID  = "https://idp.cloud-a.example"
)

func setupWIT(t *testing.T) (string, *keys.ECKeyPair) {
	t.Helper()
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()
	issuer := wit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	witToken, err := issuer.Issue(wit.IssueOptions{
		Subject:     "spiffe://cloud-a.example/workload-a",
		WorkloadKey: workloadKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue WIT: %v", err)
	}
	return witToken, workloadKP
}

func defaultGenOpts(witToken string, workloadKP *keys.ECKeyPair) wpt.GenerateOptions {
	return wpt.GenerateOptions{
		TargetURI:   targetURI,
		WIT:         witToken,
		WorkloadKey: workloadKP.Private,
		TTL:         5 * time.Minute,
	}
}


func TestWPT_HappyPath(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	wptToken, err := wpt.Generate(defaultGenOpts(witToken, workloadKP))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	v := wpt.NewValidator()
	claims, err := v.Validate(wpt.ValidateOptions{
		WPTString:        wptToken,
		WITString:        witToken,
		WorkloadPublicKey: workloadKP.Public,
		RequestURI:       targetURI,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims == nil {
		t.Fatal("expected non-nil claims")
	}
}

func TestWPT_AudienceMismatch(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	wptToken, _ := wpt.Generate(defaultGenOpts(witToken, workloadKP))

	v := wpt.NewValidator()
	_, err := v.Validate(wpt.ValidateOptions{
		WPTString:        wptToken,
		WITString:        witToken,
		WorkloadPublicKey: workloadKP.Public,
		RequestURI:       "https://other-service.example/api",
	})
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
}

func TestWPT_WthMismatch(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	wptToken, _ := wpt.Generate(defaultGenOpts(witToken, workloadKP))

	// Validate with a different WIT string → wth won't match
	v := wpt.NewValidator()
	_, err := v.Validate(wpt.ValidateOptions{
		WPTString:        wptToken,
		WITString:        witToken + "tampered",
		WorkloadPublicKey: workloadKP.Public,
		RequestURI:       targetURI,
	})
	if err == nil {
		t.Fatal("expected error for wth mismatch")
	}
}

func TestWPT_Expired(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	wptToken, _ := wpt.Generate(wpt.GenerateOptions{
		TargetURI:   targetURI,
		WIT:         witToken,
		WorkloadKey: workloadKP.Private,
		TTL:         -time.Second,
	})

	v := wpt.NewValidator()
	_, err := v.Validate(wpt.ValidateOptions{
		WPTString:        wptToken,
		WITString:        witToken,
		WorkloadPublicKey: workloadKP.Public,
		RequestURI:       targetURI,
	})
	if err == nil {
		t.Fatal("expected error for expired WPT")
	}
}

func TestWPT_WrongKey(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	wptToken, _ := wpt.Generate(defaultGenOpts(witToken, workloadKP))

	otherKP, _ := keys.GenerateECKeyPair()
	v := wpt.NewValidator()
	_, err := v.Validate(wpt.ValidateOptions{
		WPTString:        wptToken,
		WITString:        witToken,
		WorkloadPublicKey: otherKP.Public,
		RequestURI:       targetURI,
	})
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestWPT_ReplayProtection(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	wptToken, _ := wpt.Generate(defaultGenOpts(witToken, workloadKP))

	v := wpt.NewValidator()
	opts := wpt.ValidateOptions{
		WPTString:        wptToken,
		WITString:        witToken,
		WorkloadPublicKey: workloadKP.Public,
		RequestURI:       targetURI,
		CheckReplay:      true,
	}

	if _, err := v.Validate(opts); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	_, err := v.Validate(opts)
	if err == nil {
		t.Fatal("expected replay error on second use")
	}
}

func TestWPT_TypHeader(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	wptToken, _ := wpt.Generate(defaultGenOpts(witToken, workloadKP))

	p := jwt.NewParser()
	var claims wpt.Claims
	tok, _, err := p.ParseUnverified(wptToken, &claims)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	typ, _ := tok.Header["typ"].(string)
	if typ != "application/wpt+jwt" {
		t.Fatalf("expected typ=application/wpt+jwt, got %q", typ)
	}
}

func TestWPT_InputValidation_NoTargetURI(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	_, err := wpt.Generate(wpt.GenerateOptions{
		WIT:         witToken,
		WorkloadKey: workloadKP.Private,
	})
	if err == nil {
		t.Fatal("expected error when TargetURI is missing")
	}
}

func TestWPT_InputValidation_NoWIT(t *testing.T) {
	_, workloadKP := setupWIT(t)
	_, err := wpt.Generate(wpt.GenerateOptions{
		TargetURI:   targetURI,
		WorkloadKey: workloadKP.Private,
	})
	if err == nil {
		t.Fatal("expected error when WIT is missing")
	}
}

func TestWPT_InputValidation_NoKey(t *testing.T) {
	witToken, _ := setupWIT(t)
	_, err := wpt.Generate(wpt.GenerateOptions{
		TargetURI: targetURI,
		WIT:       witToken,
	})
	if err == nil {
		t.Fatal("expected error when WorkloadKey is missing")
	}
}

func TestWPT_TxnTokenBinding_HappyPath(t *testing.T) {
	witToken, workloadKP := setupWIT(t)
	txnToken := "fake.txn.token.for.test"

	wptToken, err := wpt.Generate(wpt.GenerateOptions{
		TargetURI:   targetURI,
		WIT:         witToken,
		WorkloadKey: workloadKP.Private,
		TxnToken:    txnToken,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	v := wpt.NewValidator()
	claims, err := v.Validate(wpt.ValidateOptions{
		WPTString:         wptToken,
		WITString:         witToken,
		WorkloadPublicKey: workloadKP.Public,
		RequestURI:        targetURI,
		TxnToken:          txnToken,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Tth == "" {
		t.Error("expected tth claim to be set")
	}
}

func TestWPT_TxnTokenBinding_Mismatch(t *testing.T) {
	witToken, workloadKP := setupWIT(t)

	wptToken, _ := wpt.Generate(wpt.GenerateOptions{
		TargetURI:   targetURI,
		WIT:         witToken,
		WorkloadKey: workloadKP.Private,
		TxnToken:    "original.txn.token",
	})

	v := wpt.NewValidator()
	_, err := v.Validate(wpt.ValidateOptions{
		WPTString:         wptToken,
		WITString:         witToken,
		WorkloadPublicKey: workloadKP.Public,
		RequestURI:        targetURI,
		TxnToken:          "different.txn.token",
	})
	if err == nil {
		t.Fatal("expected error for tth mismatch")
	}
}

func TestWPT_TxnTokenBinding_NotRequired(t *testing.T) {
	// WPT without tth should still validate when no TxnToken is presented.
	witToken, workloadKP := setupWIT(t)
	wptToken, _ := wpt.Generate(defaultGenOpts(witToken, workloadKP))

	v := wpt.NewValidator()
	_, err := v.Validate(wpt.ValidateOptions{
		WPTString:         wptToken,
		WITString:         witToken,
		WorkloadPublicKey: workloadKP.Public,
		RequestURI:        targetURI,
		// No TxnToken: tth not checked
	})
	if err != nil {
		t.Fatalf("expected validation without tth to succeed: %v", err)
	}
}

func TestWPT_EndToEnd(t *testing.T) {
	// Full flow: issue WIT, generate WPT, validate both together
	idpKP, _ := keys.GenerateECKeyPair()
	workloadKP, _ := keys.GenerateECKeyPair()

	issuer := wit.NewIssuer(issuerID, idpKP.Private, time.Hour)
	witToken, err := issuer.Issue(wit.IssueOptions{
		Subject:     "spiffe://cloud-a.example/svc/billing",
		WorkloadKey: workloadKP.Public,
		Audiences:   []string{targetURI},
	})
	if err != nil {
		t.Fatalf("Issue WIT: %v", err)
	}

	wptToken, err := wpt.Generate(wpt.GenerateOptions{
		TargetURI:   targetURI,
		WIT:         witToken,
		WorkloadKey: workloadKP.Private,
		TTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Generate WPT: %v", err)
	}

	// Validate WIT first
	witValidator := wit.NewValidator(issuerID, idpKP.Public)
	witResult, err := witValidator.Validate(witToken)
	if err != nil {
		t.Fatalf("Validate WIT: %v", err)
	}

	// Validate WPT using the key extracted from cnf
	wptValidator := wpt.NewValidator()
	claims, err := wptValidator.Validate(wpt.ValidateOptions{
		WPTString:        wptToken,
		WITString:        witToken,
		WorkloadPublicKey: witResult.WorkloadKey,
		RequestURI:       targetURI,
		CheckReplay:      true,
	})
	if err != nil {
		t.Fatalf("Validate WPT: %v", err)
	}
	if claims.Wth == "" {
		t.Fatal("expected non-empty wth claim")
	}
}
