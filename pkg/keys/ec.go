package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// ECKeyPair holds an EC P-256 private and public key pair.
type ECKeyPair struct {
	Private *ecdsa.PrivateKey
	Public  *ecdsa.PublicKey
}

// JWK represents a JSON Web Key for EC P-256. Alg is always "ES256".
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg"`
}

// GenerateECKeyPair generates a new EC P-256 key pair.
func GenerateECKeyPair() (*ECKeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate EC key: %w", err)
	}
	return &ECKeyPair{Private: priv, Public: &priv.PublicKey}, nil
}

// PublicKeyToJWK serializes an EC P-256 public key to JWK.
// X and Y coordinates are left-padded to 32 bytes per RFC 7518 §6.2.
func PublicKeyToJWK(pub *ecdsa.PublicKey, kid string) (*JWK, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("key must be EC P-256")
	}
	return &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64urlPad(pub.X, 32),
		Y:   base64urlPad(pub.Y, 32),
		Kid: kid,
		Alg: "ES256",
	}, nil
}

// JWKToPublicKey deserializes a JWK to an EC P-256 public key.
// Point validity is verified via crypto/ecdh, which performs a constant-time on-curve check.
func JWKToPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported key type: kty=%s crv=%s", jwk.Kty, jwk.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decode X: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("decode Y: %w", err)
	}

	// Validate that (X, Y) is on the P-256 curve using crypto/ecdh uncompressed point encoding.
	// crypto/ecdh.PublicKey.SetBytes performs a constant-time on-curve check.
	uncompressed := make([]byte, 1+32+32)
	uncompressed[0] = 0x04
	// Left-pad X and Y to 32 bytes each.
	copy(uncompressed[1+32-len(xBytes):33], xBytes)
	copy(uncompressed[33+32-len(yBytes):65], yBytes)
	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, errors.New("point is not on P-256 curve")
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// JWKFromRawMessage parses a json.RawMessage into a JWK.
func JWKFromRawMessage(raw json.RawMessage) (*JWK, error) {
	var jwk JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("unmarshal JWK: %w", err)
	}
	return &jwk, nil
}

// SaveECPrivateKey serializes an EC private key to a PEM file (mode 0600).
func SaveECPrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// LoadECPrivateKey reads an EC private key from a PEM file.
func LoadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("no EC PRIVATE KEY block in file")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	return key, nil
}

// base64urlPad encodes n as base64url, left-padding to size bytes.
func base64urlPad(n *big.Int, size int) string {
	b := n.Bytes()
	if len(b) < size {
		pad := make([]byte, size-len(b))
		b = append(pad, b...)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
