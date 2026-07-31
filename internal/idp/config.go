package idp

import (
	"time"

	"github.com/example/wimse-identity-fabric/pkg/keys"
)

// IdPConfig holds configuration for the Identity Provider.
type IdPConfig struct {
	TrustDomain     string
	IssuerID        string // e.g. "https://idp.cloud-a.example"
	SigningKey       *keys.ECKeyPair
	TokenTTL        time.Duration
	AllowedSubjects []string // empty = allow all (PoC mode)

	// Federation fields (OID-FED 1.0 Phase 6).
	// OrganizationName is included in the entity configuration metadata.
	OrganizationName string
	// AuthorityHints names the Trust Anchors that govern this IdP.
	// Empty means this IdP acts as its own Trust Anchor (standalone).
	AuthorityHints []string
	// EntityConfigTTL is how long issued Entity Configuration JWTs are valid.
	// Defaults to 24h.
	EntityConfigTTL time.Duration
	// TrustAnchorSubjects maps subject entity IDs to their Subordinate Statement JWTs.
	// Populated when this IdP also acts as a Trust Anchor for other entities.
	TrustAnchorSubjects map[string]string // subjectID → signed SS JWT
}

// subjectAllowed reports whether the given subject is permitted.
func (c *IdPConfig) subjectAllowed(subject string) bool {
	if len(c.AllowedSubjects) == 0 {
		return true
	}
	for _, s := range c.AllowedSubjects {
		if s == subject {
			return true
		}
	}
	return false
}
