// Package sdwit implements Phase 5 of the WIMSE PoC: SD-JWT-VC Workload Identity Tokens.
//
// An SD-WIT (Selective Disclosure Workload Identity Token) extends the plain WIT
// (wit+jwt) from Phase 1 with selective disclosure based on the SD-JWT standard
// (RFC 9278 / draft-ietf-oauth-selective-disclosure-jwt).
//
// Format: <Issuer-signed JWT>~<Disclosure1>~<Disclosure2>~...~
//
// The Issuer-signed JWT uses:
//   - typ: "wit+sd-jwt"
//   - alg: ES256
//   - Standard claims: iss, iat, nbf, exp, jti, aud (always visible)
//   - cnf.jwk: workload public key (always visible — required for WPT binding)
//   - _sd: array of SHA-256 hashes of selectively disclosable claims
//   - _sd_alg: "sha-256"
//
// Selectively disclosable claims (configured per issuance): sub, trust_domain, roles.
//
// Privacy model:
//   - The Holder (workload) receives the full SD-JWT with all disclosures.
//   - When calling a high-trust service: present all disclosures.
//   - When calling a lower-trust service: use Present() to strip unwanted disclosures,
//     revealing only e.g. sub while keeping roles and trust_domain private.
//
// Integration with WPT:
//   - The WPT wth claim continues to hash the full SD-JWT string (including all
//     disclosures), which the Holder possesses and uses unchanged for proof-of-possession.
//   - Selective presentation does not affect WPT generation or validation.
//
// SPICE alignment:
//   - This implements the selective disclosure pattern described by the IETF SPICE WG.
//   - The cnf key confirmation mechanism is identical to SD-CWT (CBOR analog).
//   - See: draft-ietf-spice-sd-cwt, draft-mw-wimse-transitive-attestation.
package sdwit

import "crypto/ecdsa"

// sdAlg is the hash algorithm identifier placed in the _sd_alg claim.
const sdAlg = "sha-256"

// WITTyp is the typ header value for SD-JWT Workload Identity Tokens.
const WITTyp = "wit+sd-jwt"

// SelectiveClaims controls which optional WIT claims are made selectively disclosable.
// Claims set to true are replaced by a hash in the JWT payload; the actual value
// is carried in a disclosure string appended after the ~ separator.
// Claims set to false are embedded directly in the JWT payload (always visible).
type SelectiveClaims struct {
	Sub         bool // spiffe:// or wimse:// subject URI
	TrustDomain bool // trust domain string
	Roles       bool // custom roles claim ([]string)
}

// VerifiedClaims holds claims extracted after validating an SD-WIT and unpacking
// the provided disclosures. Only claims with a matching disclosure are populated.
type VerifiedClaims struct {
	// Always-visible standard claims
	Issuer    string
	Audiences []string
	Expiry    int64

	// Conditionally visible — only set when the holder included the disclosure
	Subject     string   // empty if not disclosed
	TrustDomain string   // empty if not disclosed
	Roles       []string // nil if not disclosed

	// WorkloadKey is always extracted from cnf.jwk; it is never selectively hidden
	// because the verifier needs it to validate the accompanying WPT.
	WorkloadKey *ecdsa.PublicKey
}
