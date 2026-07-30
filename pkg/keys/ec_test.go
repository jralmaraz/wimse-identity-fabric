package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestGenerateECKeyPair(t *testing.T) {
	kp, err := GenerateECKeyPair()
	if err != nil {
		t.Fatalf("GenerateECKeyPair: %v", err)
	}
	if kp.Private == nil || kp.Public == nil {
		t.Fatal("nil key in pair")
	}
	if kp.Public.Curve != elliptic.P256() {
		t.Fatal("expected P-256 curve")
	}
}

func TestPublicKeyToJWKRoundTrip(t *testing.T) {
	kp, _ := GenerateECKeyPair()
	jwk, err := PublicKeyToJWK(kp.Public, "test-kid")
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" || jwk.Kid != "test-kid" {
		t.Fatalf("unexpected JWK fields: %+v", jwk)
	}

	pub2, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatalf("JWKToPublicKey: %v", err)
	}
	if pub2.X.Cmp(kp.Public.X) != 0 || pub2.Y.Cmp(kp.Public.Y) != 0 {
		t.Fatal("round-trip key mismatch")
	}
}

func TestPublicKeyToJWK_AlgField(t *testing.T) {
	kp, _ := GenerateECKeyPair()
	jwk, _ := PublicKeyToJWK(kp.Public, "")
	if jwk.Alg != "ES256" {
		t.Fatalf("expected Alg=ES256, got %q", jwk.Alg)
	}
}

func TestPublicKeyToJWK_LeadingZeroPadding(t *testing.T) {
	// X=42, Y=99 are tiny values; PublicKeyToJWK should pad them to 32 bytes.
	smallKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(42), Y: big.NewInt(99)}
	jwk, err := PublicKeyToJWK(smallKey, "")
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	xBytes, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	if len(xBytes) != 32 {
		t.Fatalf("X padded to %d bytes, want 32", len(xBytes))
	}
	yBytes, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
	if len(yBytes) != 32 {
		t.Fatalf("Y padded to %d bytes, want 32", len(yBytes))
	}
}

func TestJWKToPublicKey_InvalidCurve(t *testing.T) {
	jwk := &JWK{Kty: "EC", Crv: "P-384", X: "x", Y: "y", Alg: "ES384"}
	_, err := JWKToPublicKey(jwk)
	if err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

func TestJWKToPublicKey_InvalidPoint(t *testing.T) {
	// (1,1) is not on P-256
	x := base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes())
	y := base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes())
	jwk := &JWK{Kty: "EC", Crv: "P-256", X: x, Y: y, Alg: "ES256"}
	_, err := JWKToPublicKey(jwk)
	if err == nil {
		t.Fatal("expected error for point not on curve")
	}
}

func TestJWKFromRawMessage(t *testing.T) {
	kp, _ := GenerateECKeyPair()
	jwk, _ := PublicKeyToJWK(kp.Public, "k1")
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	parsed, err := JWKFromRawMessage(raw)
	if err != nil {
		t.Fatalf("JWKFromRawMessage: %v", err)
	}
	if parsed.Kid != "k1" || parsed.Alg != "ES256" {
		t.Fatalf("unexpected fields: %+v", parsed)
	}
}

func TestECKeySignVerify(t *testing.T) {
	kp, err := GenerateECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, kp.Private, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.Verify(kp.Public, msg, r, s) {
		t.Fatal("signature verification failed")
	}
}
