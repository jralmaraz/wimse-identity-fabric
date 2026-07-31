package exchange

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/example/wimse-identity-fabric/pkg/federation"
)

// TrustPolicy defines allowed cross-domain subject mappings.
//
// Phase 4 (static): AllowedIssuers maps issuer IDs to pre-configured public keys.
// Phase 6 (dynamic): Resolver resolves issuer keys via OID-FED trust chains.
// Both can coexist — static entries take priority (faster, no network).
type TrustPolicy struct {
	// AllowedIssuers maps issuer IDs to their public keys (static, Phase 4).
	AllowedIssuers map[string]*ecdsa.PublicKey

	// Resolver resolves unknown issuers via OID-FED trust chains (dynamic, Phase 6).
	// If nil, only AllowedIssuers is consulted.
	Resolver federation.Resolver

	// AllowedSubjects is an optional allow-list of source subjects.
	// Empty means all subjects from trusted issuers are accepted.
	AllowedSubjects []string

	// SubjectMap provides optional subject rewrite rules.
	// If nil, the subject passes through unchanged.
	SubjectMap map[string]string
}

// Allows reports whether the given issuer and subject are trusted.
// It does not resolve the issuer key — call ResolveIssuerKey first.
func (p *TrustPolicy) Allows(issuer, subject string) bool {
	// Check static issuers.
	_, staticOK := p.AllowedIssuers[issuer]
	// For federation-resolved issuers, the handler calls ResolveIssuerKey first;
	// if we reached Allows(), the issuer was already validated.
	if !staticOK && p.Resolver == nil {
		return false
	}
	if len(p.AllowedSubjects) == 0 {
		return true
	}
	for _, s := range p.AllowedSubjects {
		if s == subject {
			return true
		}
	}
	return false
}

// MapSubject applies the subject rewrite rules. If no rule matches, subject is returned unchanged.
func (p *TrustPolicy) MapSubject(subject string) string {
	if p.SubjectMap == nil {
		return subject
	}
	if mapped, ok := p.SubjectMap[subject]; ok {
		return mapped
	}
	return subject
}

// IssuerKey returns the statically-configured public key for the given issuer, or nil.
// Kept for backward compatibility (Phase 4 tests).
func (p *TrustPolicy) IssuerKey(issuer string) *ecdsa.PublicKey {
	return p.AllowedIssuers[issuer]
}

// ResolveIssuerKey returns the public key for the issuer, consulting the static
// map first and falling back to the OID-FED resolver if a Resolver is configured.
// Returns an error if the issuer is not trusted by any mechanism.
func (p *TrustPolicy) ResolveIssuerKey(ctx context.Context, issuer string) (*ecdsa.PublicKey, error) {
	// Static map (Phase 4) — always checked first.
	if k, ok := p.AllowedIssuers[issuer]; ok {
		return k, nil
	}
	// Federation resolver (Phase 6).
	if p.Resolver != nil {
		entity, err := p.Resolver.Resolve(ctx, issuer)
		if err != nil {
			return nil, fmt.Errorf("federation resolve %q: %w", issuer, err)
		}
		pub, err := entity.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("extract key for %q from federation: %w", issuer, err)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("issuer %q not trusted (not in AllowedIssuers and no Resolver configured)", issuer)
}
