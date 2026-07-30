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
