package httpsig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// VerifyOptions holds parameters for verifying an inbound signed request.
type VerifyOptions struct {
	Request        *http.Request
	WorkloadPubKey *ecdsa.PublicKey
	ExpectedAud    string
	CheckReplay    bool
}

// VerifiedRequest is returned by Verifier.Verify on success.
type VerifiedRequest struct {
	WIT     string
	Subject string
	Nonce   string
	Aud     string
}

// Verifier validates WIMSE HTTP Message Signatures.
type Verifier struct {
	store NonceStore
}

// NewVerifier returns a Verifier backed by an in-memory nonce store.
func NewVerifier() *Verifier {
	return &Verifier{store: NewInMemoryNonceStore()}
}

// NewVerifierWithStore returns a Verifier backed by the provided NonceStore.
func NewVerifierWithStore(s NonceStore) *Verifier {
	return &Verifier{store: s}
}

// Verify checks the Signature-Input and Signature headers, reconstructs the
// signature base, verifies the ECDSA signature, and enforces WIMSE constraints.
func (v *Verifier) Verify(opts VerifyOptions) (*VerifiedRequest, error) {
	if opts.Request == nil {
		return nil, errors.New("request is required")
	}
	if opts.WorkloadPubKey == nil {
		return nil, errors.New("workload public key is required")
	}
	if opts.ExpectedAud == "" {
		return nil, errors.New("expected audience is required")
	}

	witVal := opts.Request.Header.Get(headerWIT)
	if witVal == "" {
		return nil, errors.New("missing Workload-Identity-Token header")
	}

	inputHdr := opts.Request.Header.Get(headerSigInput)
	if inputHdr == "" {
		return nil, errors.New("missing Signature-Input header")
	}
	sigHdr := opts.Request.Header.Get(headerSig)
	if sigHdr == "" {
		return nil, errors.New("missing Signature header")
	}

	// Parse Signature-Input: sig1=(<comps>);params...
	comps, p, err := parseSigInput(inputHdr)
	if err != nil {
		return nil, fmt.Errorf("parse Signature-Input: %w", err)
	}

	// Enforce required WIMSE params.
	if p.aud != opts.ExpectedAud {
		return nil, fmt.Errorf("audience mismatch: got %q want %q", p.aud, opts.ExpectedAud)
	}

	// Enforce freshness.
	now := time.Now().Unix()
	if p.created > now+5 {
		return nil, errors.New("signature created in the future")
	}
	if p.expires > 0 && now > p.expires {
		return nil, errors.New("signature expired")
	}
	if p.nonce == "" {
		return nil, errors.New("missing nonce")
	}

	// Validate required covered components.
	required := map[string]bool{"@method": false, "@path": false, "@query": false, "workload-identity-token": false}
	for _, c := range comps {
		if _, ok := required[c]; ok {
			required[c] = true
		}
	}
	for comp, found := range required {
		if !found {
			return nil, fmt.Errorf("required component %q missing from signature", comp)
		}
	}

	// Reconstruct signature base.
	base, err := buildSignatureBase(opts.Request, comps, p)
	if err != nil {
		return nil, fmt.Errorf("reconstruct signature base: %w", err)
	}

	// Parse raw signature.
	rawSig, err := parseSigHeader(sigHdr)
	if err != nil {
		return nil, fmt.Errorf("parse Signature header: %w", err)
	}

	// Verify ECDSA signature.
	if err := verifyECDSA(opts.WorkloadPubKey, []byte(base), rawSig); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Replay protection.
	if opts.CheckReplay {
		expTime := time.Now().Add(10 * time.Minute) // bounded by expiry in practice
		if p.expires > 0 {
			expTime = time.Unix(p.expires, 0)
		}
		if err := v.store.Record(p.nonce, expTime); err != nil {
			return nil, fmt.Errorf("replay check: %w", err)
		}
	}

	// Extract subject from WIT (trust already established by the caller via WIT validation).
	sub, err := subjectFromWIT(witVal)
	if err != nil {
		return nil, fmt.Errorf("extract subject from WIT: %w", err)
	}

	return &VerifiedRequest{
		WIT:     witVal,
		Subject: sub,
		Nonce:   p.nonce,
		Aud:     p.aud,
	}, nil
}

// parsedSigInput extends sigParams with tag.
type parsedSigInput struct {
	sigParams
	tag string
}

// parseSigInput parses: sig1=("comp1" "comp2" ...);created=T;expires=T;nonce="N";tag="T";wimse-aud="A"
func parseSigInput(hdr string) ([]string, sigParams, error) {
	// Strip sigLabel prefix.
	prefix := sigLabel + "="
	if !strings.HasPrefix(hdr, prefix) {
		return nil, sigParams{}, fmt.Errorf("expected %q prefix in Signature-Input", prefix)
	}
	rest := hdr[len(prefix):]

	// Split components list from params at ");".
	listEnd := strings.Index(rest, ")")
	if listEnd < 0 || !strings.HasPrefix(rest, "(") {
		return nil, sigParams{}, errors.New("malformed component list in Signature-Input")
	}
	listPart := rest[1:listEnd]       // inside the parens
	paramPart := rest[listEnd+1:]     // starts with ";"

	// Parse component IDs: space-separated double-quoted strings.
	var comps []string
	for _, token := range strings.Fields(listPart) {
		token = strings.Trim(token, `"`)
		if token != "" {
			comps = append(comps, token)
		}
	}

	// Parse params: ;key=value or ;key="value"
	var p parsedSigInput
	for _, kv := range strings.Split(strings.TrimPrefix(paramPart, ";"), ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			continue
		}
		k, v := kv[:idx], kv[idx+1:]
		v = strings.Trim(v, `"`)
		switch k {
		case "created":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, sigParams{}, fmt.Errorf("parse created: %w", err)
			}
			p.created = n
		case "expires":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, sigParams{}, fmt.Errorf("parse expires: %w", err)
			}
			p.expires = n
		case "nonce":
			p.nonce = v
		case "tag":
			p.tag = v
		case "wimse-aud":
			p.aud = v
		}
	}
	if p.tag != wimseTag {
		return nil, sigParams{}, fmt.Errorf("tag %q not recognized", p.tag)
	}
	return comps, p.sigParams, nil
}

// parseSigHeader extracts the raw signature bytes from: sig1=:<base64>:
func parseSigHeader(hdr string) ([]byte, error) {
	prefix := sigLabel + "=:"
	if !strings.HasPrefix(hdr, prefix) {
		return nil, fmt.Errorf("expected %q prefix in Signature header", prefix)
	}
	inner := hdr[len(prefix):]
	inner = strings.TrimSuffix(inner, ":")
	b, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	return b, nil
}

// verifyECDSA checks a raw 64-byte (r||s) ECDSA-P256/SHA-256 signature.
func verifyECDSA(pub *ecdsa.PublicKey, data, rawSig []byte) error {
	if len(rawSig) != 64 {
		return fmt.Errorf("unexpected signature length %d, want 64", len(rawSig))
	}
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	digest := sha256.Sum256(data)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

// subjectFromWIT extracts the sub claim from a WIT JWT without re-verifying
// the signature. Trust is established by the caller who supplied WorkloadPubKey
// extracted from the already-validated WIT.
func subjectFromWIT(witJWT string) (string, error) {
	p := jwt.NewParser()
	var claims jwt.RegisteredClaims
	_, _, err := p.ParseUnverified(witJWT, &claims)
	if err != nil {
		return "", fmt.Errorf("parse WIT claims: %w", err)
	}
	return claims.Subject, nil
}
