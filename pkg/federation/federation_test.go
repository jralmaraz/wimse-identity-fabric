package federation_test

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/example/wimse-identity-fabric/pkg/federation"
	"github.com/example/wimse-identity-fabric/pkg/keys"
)

const (
	anchorID  = "https://trust-anchor.corporate.example"
	idpAID    = "https://idp.cloud-a.example"
	idpBID    = "https://idp.cloud-b.example"
	idpAOrg   = "Acme Corp Cloud A"
)

type env struct {
	anchorKP *keys.ECKeyPair
	idpAKP   *keys.ECKeyPair
	idpBKP   *keys.ECKeyPair
}

func setupEnv(t *testing.T) *env {
	t.Helper()
	anchorKP, _ := keys.GenerateECKeyPair()
	idpAKP, _ := keys.GenerateECKeyPair()
	idpBKP, _ := keys.GenerateECKeyPair()
	return &env{anchorKP: anchorKP, idpAKP: idpAKP, idpBKP: idpBKP}
}

func buildAnchors(e *env) map[string]*ecdsa.PublicKey {
	return map[string]*ecdsa.PublicKey{anchorID: e.anchorKP.Public}
}

func TestBuildAndParseEntityConfiguration(t *testing.T) {
	e := setupEnv(t)

	ecJWT, err := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	if err != nil {
		t.Fatalf("BuildEntityConfiguration: %v", err)
	}

	ec, err := federation.ParseEntityConfiguration(ecJWT)
	if err != nil {
		t.Fatalf("ParseEntityConfiguration: %v", err)
	}
	if ec.Issuer != idpAID {
		t.Errorf("iss: want %q got %q", idpAID, ec.Issuer)
	}
	if ec.Subject != idpAID {
		t.Errorf("sub: want %q got %q", idpAID, ec.Subject)
	}
	if len(ec.JWKS.Keys) != 1 {
		t.Errorf("JWKS.Keys: want 1 got %d", len(ec.JWKS.Keys))
	}
	if len(ec.AuthorityHints) != 1 || ec.AuthorityHints[0] != anchorID {
		t.Errorf("authority_hints: want [%q] got %v", anchorID, ec.AuthorityHints)
	}
	if ec.Metadata == nil || ec.Metadata.OpenIDProvider == nil {
		t.Error("expected metadata.openid_provider to be present")
	}
	if ec.Metadata.OpenIDProvider.Issuer != idpAID {
		t.Errorf("metadata.openid_provider.issuer: want %q got %q", idpAID, ec.Metadata.OpenIDProvider.Issuer)
	}
}

func TestVerifyEntityConfiguration_CorrectKey(t *testing.T) {
	e := setupEnv(t)
	ecJWT, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	ec, err := federation.VerifyEntityConfiguration(ecJWT, e.idpAKP.Public)
	if err != nil {
		t.Fatalf("VerifyEntityConfiguration: %v", err)
	}
	if ec.Issuer != idpAID {
		t.Errorf("iss: want %q got %q", idpAID, ec.Issuer)
	}
}

func TestVerifyEntityConfiguration_WrongKey(t *testing.T) {
	e := setupEnv(t)
	ecJWT, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	_, err := federation.VerifyEntityConfiguration(ecJWT, e.idpBKP.Public)
	if err == nil {
		t.Error("expected error when verifying EC with wrong key")
	}
}

func TestBuildAndVerifySubordinateStatement(t *testing.T) {
	e := setupEnv(t)

	ssJWT, err := federation.BuildSubordinateStatement(
		anchorID, idpAID,
		e.idpAKP.Public, "idpa-key",
		e.anchorKP.Private, "anchor-key",
		time.Hour,
	)
	if err != nil {
		t.Fatalf("BuildSubordinateStatement: %v", err)
	}

	ss, err := federation.VerifySubordinateStatement(ssJWT, e.anchorKP.Public)
	if err != nil {
		t.Fatalf("VerifySubordinateStatement: %v", err)
	}
	if ss.Issuer != anchorID {
		t.Errorf("iss: want %q got %q", anchorID, ss.Issuer)
	}
	if ss.Subject != idpAID {
		t.Errorf("sub: want %q got %q", idpAID, ss.Subject)
	}
	if len(ss.JWKS.Keys) != 1 {
		t.Errorf("JWKS.Keys: want 1 got %d", len(ss.JWKS.Keys))
	}
}

func TestVerifySubordinateStatement_WrongKey(t *testing.T) {
	e := setupEnv(t)
	ssJWT, _ := federation.BuildSubordinateStatement(
		anchorID, idpAID,
		e.idpAKP.Public, "idpa-key",
		e.anchorKP.Private, "anchor-key",
		time.Hour,
	)
	_, err := federation.VerifySubordinateStatement(ssJWT, e.idpBKP.Public)
	if err == nil {
		t.Error("expected error when verifying SS with wrong key")
	}
}

func TestInMemoryResolver_HappyPath(t *testing.T) {
	e := setupEnv(t)
	resolver := makeResolver(t, e)

	entity, err := resolver.Resolve(context.Background(), idpAID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(entity.JWKS) != 1 {
		t.Errorf("JWKS count: want 1 got %d", len(entity.JWKS))
	}
	pub, err := entity.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
	// The resolved key must equal IdP-A's actual public key.
	if pub.X.Cmp(e.idpAKP.Public.X) != 0 || pub.Y.Cmp(e.idpAKP.Public.Y) != 0 {
		t.Error("resolved key does not match IdP-A's public key")
	}
}

func TestInMemoryResolver_UnknownEntity(t *testing.T) {
	e := setupEnv(t)
	resolver := federation.NewInMemoryResolver(buildAnchors(e))
	_, err := resolver.Resolve(context.Background(), "https://rogue.example")
	if err == nil {
		t.Error("expected error for unknown entity")
	}
}

func TestInMemoryResolver_TamperedEC(t *testing.T) {
	e := setupEnv(t)

	// EC signed by the wrong key but claiming to be IdP-A.
	tamperedEC, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpBKP.Private, "wrong-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	// SS still certifies IdP-A's real key.
	ssJWT, _ := federation.BuildSubordinateStatement(
		anchorID, idpAID,
		e.idpAKP.Public, "idpa-key",
		e.anchorKP.Private, "anchor-key",
		time.Hour,
	)

	resolver := federation.NewInMemoryResolver(buildAnchors(e))
	resolver.RegisterEntityConfig(idpAID, tamperedEC)
	resolver.RegisterSubordinateStatement(idpAID, ssJWT)

	_, err := resolver.Resolve(context.Background(), idpAID)
	if err == nil {
		t.Error("expected error: EC key does not match what SS certified")
	}
}

func TestInMemoryResolver_UntrustedAnchor(t *testing.T) {
	e := setupEnv(t)
	rogueKP, _ := keys.GenerateECKeyPair()

	ecJWT, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{"https://rogue-anchor.example"}, time.Hour, // wrong anchor hint
	)
	ssJWT, _ := federation.BuildSubordinateStatement(
		"https://rogue-anchor.example", idpAID,
		e.idpAKP.Public, "idpa-key",
		rogueKP.Private, "rogue-key",
		time.Hour,
	)

	// Resolver only trusts the real anchor — rogue anchor unknown.
	resolver := federation.NewInMemoryResolver(buildAnchors(e))
	resolver.RegisterEntityConfig(idpAID, ecJWT)
	resolver.RegisterSubordinateStatement(idpAID, ssJWT)

	_, err := resolver.Resolve(context.Background(), idpAID)
	if err == nil {
		t.Error("expected error: rogue anchor not trusted")
	}
}

func TestInMemoryResolver_Caching(t *testing.T) {
	e := setupEnv(t)
	resolver := makeResolver(t, e)

	e1, err := resolver.Resolve(context.Background(), idpAID)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	e2, err := resolver.Resolve(context.Background(), idpAID)
	if err != nil {
		t.Fatalf("second Resolve (cached): %v", err)
	}
	if len(e1.JWKS) != len(e2.JWKS) {
		t.Error("cached JWKS differs from original")
	}
}

func TestResolvedEntity_PublicKey(t *testing.T) {
	e := setupEnv(t)
	resolver := makeResolver(t, e)

	entity, err := resolver.Resolve(context.Background(), idpAID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	pub, err := entity.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !pub.Equal(e.idpAKP.Public) {
		t.Error("PublicKey() returned wrong key")
	}
}

// makeResolver builds a resolver loaded with a valid IdP-A trust chain.
func makeResolver(t *testing.T, e *env) *federation.InMemoryResolver {
	t.Helper()
	resolver := federation.NewInMemoryResolver(buildAnchors(e))

	ecJWT, err := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	if err != nil {
		t.Fatalf("build EC: %v", err)
	}
	ssJWT, err := federation.BuildSubordinateStatement(
		anchorID, idpAID,
		e.idpAKP.Public, "idpa-key",
		e.anchorKP.Private, "anchor-key",
		time.Hour,
	)
	if err != nil {
		t.Fatalf("build SS: %v", err)
	}
	resolver.RegisterEntityConfig(idpAID, ecJWT)
	resolver.RegisterSubordinateStatement(idpAID, ssJWT)
	return resolver
}
