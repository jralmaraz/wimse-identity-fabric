package wag_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/wag"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const (
	platformIssuer = "https://platform.example"
	asIssuer       = "https://as.example"
	workloadSub    = "spiffe://platform.example/workload/svc-a"
)

func setup(t *testing.T) (*wag.PlatformIssuer, *wag.AuthorizationServer) {
	t.Helper()
	platformKey := newKey(t)
	asKey := newKey(t)

	issuer := wag.NewPlatformIssuer(platformIssuer, platformKey, 0)
	as := wag.NewAuthorizationServer(asIssuer, asKey, 0)
	if err := as.RegisterPlatform(wag.PlatformRegistration{
		IssuerID:  platformIssuer,
		PublicKey: &platformKey.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}
	return issuer, as
}

func TestRoundTrip(t *testing.T) {
	issuer, as := setup(t)

	grant, err := issuer.Issue(wag.GrantOptions{
		Subject:  workloadSub,
		Audience: asIssuer,
		Scope:    "read:reports",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	resp, err := as.Exchange(grant, "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if resp.Scope != "read:reports" {
		t.Errorf("scope: got %q, want %q", resp.Scope, "read:reports")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", resp.TokenType)
	}
}

func TestRequestedScopeOverridesGrantScope(t *testing.T) {
	issuer, as := setup(t)

	grant, _ := issuer.Issue(wag.GrantOptions{
		Subject:  workloadSub,
		Audience: asIssuer,
		Scope:    "read:reports write:reports",
	})

	resp, err := as.Exchange(grant, "read:reports")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Scope != "read:reports" {
		t.Errorf("scope: got %q, want %q", resp.Scope, "read:reports")
	}
}

func TestJTIReplay(t *testing.T) {
	issuer, as := setup(t)

	grant, _ := issuer.Issue(wag.GrantOptions{
		Subject:  workloadSub,
		Audience: asIssuer,
	})

	if _, err := as.Exchange(grant, ""); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	_, err := as.Exchange(grant, "")
	if err == nil {
		t.Fatal("expected replay error, got nil")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestUnknownPlatformRejected(t *testing.T) {
	otherKey := newKey(t)
	asKey := newKey(t)

	// Issuer whose key is not registered at the AS.
	rogue := wag.NewPlatformIssuer("https://rogue.example", otherKey, 0)
	as := wag.NewAuthorizationServer(asIssuer, asKey, 0)

	grant, _ := rogue.Issue(wag.GrantOptions{
		Subject:  workloadSub,
		Audience: asIssuer,
	})

	_, err := as.Exchange(grant, "")
	if err == nil {
		t.Fatal("expected error for unknown platform, got nil")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	platformKey := newKey(t)
	wrongKey := newKey(t)
	asKey := newKey(t)

	issuer := wag.NewPlatformIssuer(platformIssuer, platformKey, 0)
	as := wag.NewAuthorizationServer(asIssuer, asKey, 0)
	// Register with a DIFFERENT key than the one signing grants.
	_ = as.RegisterPlatform(wag.PlatformRegistration{
		IssuerID:  platformIssuer,
		PublicKey: &wrongKey.PublicKey,
	})

	grant, _ := issuer.Issue(wag.GrantOptions{
		Subject:  workloadSub,
		Audience: asIssuer,
	})

	_, err := as.Exchange(grant, "")
	if err == nil {
		t.Fatal("expected signature verification error, got nil")
	}
}

func TestExpiredGrantRejected(t *testing.T) {
	platformKey := newKey(t)
	asKey := newKey(t)

	issuer := wag.NewPlatformIssuer(platformIssuer, platformKey, -1*time.Second)
	as := wag.NewAuthorizationServer(asIssuer, asKey, 0)
	_ = as.RegisterPlatform(wag.PlatformRegistration{
		IssuerID:  platformIssuer,
		PublicKey: &platformKey.PublicKey,
	})

	grant, _ := issuer.Issue(wag.GrantOptions{
		Subject:  workloadSub,
		Audience: asIssuer,
		TTL:      -1 * time.Second,
	})

	_, err := as.Exchange(grant, "")
	if err == nil {
		t.Fatal("expected error for expired grant, got nil")
	}
}

func TestDistinguishingClaimMultiTenant(t *testing.T) {
	sharedKey := newKey(t)
	asKey := newKey(t)

	// Two tenants share the same issuer identifier but different tenant values.
	tenantA := wag.NewPlatformIssuer("https://shared.example", sharedKey, 0)
	as := wag.NewAuthorizationServer(asIssuer, asKey, 0)
	// Only tenant-a is registered.
	_ = as.RegisterPlatform(wag.PlatformRegistration{
		IssuerID:            "https://shared.example",
		PublicKey:           &sharedKey.PublicKey,
		DistinguishingClaim: "tenant",
		DistinguishingValue: "tenant-a",
	})

	// Grant without distinguishing claim — should be rejected.
	grantNoTenant, _ := tenantA.Issue(wag.GrantOptions{
		Subject:  workloadSub,
		Audience: asIssuer,
	})
	if _, err := as.Exchange(grantNoTenant, ""); err == nil {
		t.Fatal("expected rejection for grant without tenant claim")
	}
}

func TestMissingSubRejected(t *testing.T) {
	issuer, as := setup(t)

	_, err := issuer.Issue(wag.GrantOptions{
		Subject:  "",
		Audience: asIssuer,
	})
	if err == nil {
		t.Fatal("expected error for empty subject")
	}

	_ = as
}

func TestMissingAudienceRejected(t *testing.T) {
	issuer, _ := setup(t)

	_, err := issuer.Issue(wag.GrantOptions{
		Subject:  workloadSub,
		Audience: "",
	})
	if err == nil {
		t.Fatal("expected error for empty audience")
	}
}
