package caep_test

import (
	"testing"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/caep"
)

func TestNewSPIFFESubject(t *testing.T) {
	s := caep.NewSPIFFESubject("spiffe://td/svc")
	if s.Format != "spiffe_id" {
		t.Errorf("Format = %q", s.Format)
	}
	if s.SPIFFEID != "spiffe://td/svc" {
		t.Errorf("SPIFFEID = %q", s.SPIFFEID)
	}
}

func TestEventTimestamps(t *testing.T) {
	now := time.Now().Unix()
	sr := caep.SessionRevokedEvent{
		Subject:        caep.NewSPIFFESubject("spiffe://td/svc"),
		Reason:         "policy violation",
		EventTimestamp: now,
	}
	if sr.EventTimestamp != now {
		t.Errorf("SessionRevoked timestamp = %d, want %d", sr.EventTimestamp, now)
	}

	cc := caep.CredentialChangeEvent{
		Subject:        caep.NewSPIFFESubject("spiffe://td/svc"),
		ChangeType:     "rotate",
		EventTimestamp: now,
	}
	if cc.ChangeType != "rotate" {
		t.Errorf("CredentialChange type = %q", cc.ChangeType)
	}
}

func TestEventTypeConstants(t *testing.T) {
	if caep.EventTypeSessionRevoked == "" || caep.EventTypeTokenClaimsChange == "" || caep.EventTypeCredentialChange == "" {
		t.Error("event type constant is empty")
	}
}
