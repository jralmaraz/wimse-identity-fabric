package exchange

import (
	"crypto/ecdsa"
)

// TrustPolicy defines allowed cross-domain subject mappings.
type TrustPolicy struct {
	// AllowedIssuers maps issuer IDs to their public keys.
	AllowedIssuers map[string]*ecdsa.PublicKey

	// AllowedSubjects is an optional allow-list of source subjects.
	// Empty means all subjects from trusted issuers are accepted.
	AllowedSubjects []string

	// SubjectMap provides optional subject rewrite rules.
	// If nil, the subject passes through unchanged.
	SubjectMap map[string]string
}

// Allows reports whether the given issuer and subject are trusted.
func (p *TrustPolicy) Allows(issuer, subject string) bool {
	if _, ok := p.AllowedIssuers[issuer]; !ok {
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

// IssuerKey returns the public key for the given issuer, or nil if not trusted.
func (p *TrustPolicy) IssuerKey(issuer string) *ecdsa.PublicKey {
	return p.AllowedIssuers[issuer]
}
