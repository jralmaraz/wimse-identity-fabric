package caep

const (
	EventTypeSessionRevoked    = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventTypeTokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	EventTypeCredentialChange  = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
)

type SubjectIdentifier struct {
	Format   string `json:"format"`
	SPIFFEID string `json:"spiffe_id,omitempty"`
	Opaque   string `json:"opaque,omitempty"`
}

func NewSPIFFESubject(spiffeID string) SubjectIdentifier {
	return SubjectIdentifier{Format: "spiffe_id", SPIFFEID: spiffeID}
}

type SessionRevokedEvent struct {
	Subject        SubjectIdentifier `json:"subject"`
	Reason         string            `json:"reason,omitempty"`
	EventTimestamp int64             `json:"event_timestamp"`
}

type TokenClaimsChangeEvent struct {
	Subject        SubjectIdentifier `json:"subject"`
	Claims         map[string]any    `json:"claims"`
	EventTimestamp int64             `json:"event_timestamp"`
}

type CredentialChangeEvent struct {
	Subject        SubjectIdentifier `json:"subject"`
	ChangeType     string            `json:"change_type"` // "issue", "rotate", "revoke"
	EventTimestamp int64             `json:"event_timestamp"`
}
