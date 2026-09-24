// Package httpsig implements the WIMSE HTTP Message Signature authentication
// profile (draft-ietf-wimse-http-signature-07) on top of RFC 9421.
//
// The workload's Workload Identity Token (WIT) is conveyed in the
// Workload-Identity-Token header. The HTTP message signature covers a fixed
// set of components and binds the request to a specific audience via the
// wimse-aud signature parameter. This is the alternative to the JWT-based WPT
// mechanism in pkg/wpt.
package httpsig

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

const (
	wimseTag              = "wimse-workload-to-workload"
	headerWIT             = "Workload-Identity-Token"
	headerSigInput        = "Signature-Input"
	headerSig             = "Signature"
	sigLabel              = "sig1"
	defaultTTL            = 5 * time.Minute
)

// SignOptions holds parameters for signing an outgoing HTTP request.
type SignOptions struct {
	Request        *http.Request
	WIT            string
	WorkloadKey    *ecdsa.PrivateKey
	TargetAudience string
	TTL            time.Duration
}

// Sign adds Workload-Identity-Token, Signature-Input, and Signature headers
// to the request in place.
func Sign(opts SignOptions) error {
	if opts.Request == nil {
		return errors.New("request is required")
	}
	if opts.WIT == "" {
		return errors.New("WIT is required")
	}
	if opts.WorkloadKey == nil {
		return errors.New("workload key is required")
	}
	if opts.TargetAudience == "" {
		return errors.New("target audience is required")
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}

	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	now := time.Now()
	p := sigParams{
		created: now.Unix(),
		expires: now.Add(ttl).Unix(),
		nonce:   nonce,
		aud:     opts.TargetAudience,
	}

	opts.Request.Header.Set(headerWIT, opts.WIT)

	comps := coveredComponents(opts.Request)
	inputVal := sigParamsLine(comps, p)
	opts.Request.Header.Set(headerSigInput, sigLabel+"="+inputVal)

	base, err := buildSignatureBase(opts.Request, comps, p)
	if err != nil {
		return fmt.Errorf("build signature base: %w", err)
	}

	sig, err := signECDSA(opts.WorkloadKey, []byte(base))
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	opts.Request.Header.Set(headerSig, sigLabel+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// signECDSA signs data with ECDSA P-256/SHA-256 and returns the raw 64-byte
// signature (r||s, each 32 bytes big-endian) per RFC 9421.
func signECDSA(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	return ecdsaRawSig(r, s), nil
}

// ecdsaRawSig encodes r and s as a fixed-width 64-byte concatenation.
func ecdsaRawSig(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	// Right-align each component in its 32-byte slot (big-endian zero-pad).
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out
}

// generateNonce returns a cryptographically random 16-byte hex nonce.
func generateNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// hex-encode the 8 bytes as 16 hex chars
	return fmt.Sprintf("%016x", binary.BigEndian.Uint64(b)), nil
}
