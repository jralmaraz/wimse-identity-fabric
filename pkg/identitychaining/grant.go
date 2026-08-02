// Package identitychaining implements cross-domain identity chaining per
// draft-ietf-oauth-identity-chaining-17.
//
// Reference: draft-ietf-oauth-identity-chaining-17 (RFC 8693 + RFC 7523 profile)
//
// # Problem
//
// When a workload in trust domain A needs to call a resource in trust domain B,
// domain B's AS will not accept domain A's WIT — the two domains have independent
// signing keys and issuer IDs. A naive solution (re-issuing the token with the same
// subject) loses the cryptographic proof that domain A validated the workload identity.
//
// # Solution
//
// Identity Chaining inserts a JWT Authorization Grant as an intermediate step:
//
//  1. Workload presents WIT-A to domain A's AS (the GrantIssuer).
//  2. Domain A validates WIT-A and issues a JWT Authorization Grant targeting domain B's
//     token endpoint. The grant carries the workload's SPIFFE ID as sub, and domain A's
//     issuer ID as iss — establishing a verifiable assertion chain.
//  3. Workload presents the grant to domain B's AS (the GrantValidator).
//  4. Domain B verifies the grant (domain A's signature), checks the target audience,
//     and issues its own access token for the workload.
//
// The grant does NOT replace the workload's WIT — it is an assertion by domain A's AS
// that it has validated the workload and delegates to domain B. Domain B controls what
// access to grant based on its own policy.
//
// # Token type
//
// The JWT Authorization Grant uses typ=jwt-authz-grant (PoC extension; the spec uses
// application/jwt; the typ value is a PoC convenience label).
package identitychaining

import "github.com/golang-jwt/jwt/v5"

// GrantTokenType is the typ header value for a JWT Authorization Grant.
const GrantTokenType = "jwt-authz-grant"

// GrantClaims is the payload of a JWT Authorization Grant.
//
// The grant is issued by domain A's AS and presented to domain B's token endpoint.
// Domain B verifies the grant signature (using domain A's public key) and extracts
// the subject (workload SPIFFE ID) to determine what access to grant.
type GrantClaims struct {
	jwt.RegisteredClaims
	// Act carries the actor that requested the grant exchange, following RFC 8693 §4.1.
	// In this PoC it is left nil; it is reserved for future delegation-chain support.
	Act *ActorClaims `json:"act,omitempty"`
}

// ActorClaims identifies the actor who requested the token exchange.
// Follows the RFC 8693 "act" claim structure.
type ActorClaims struct {
	// Sub is the SPIFFE ID of the workload that triggered the exchange.
	Sub string `json:"sub"`
}
