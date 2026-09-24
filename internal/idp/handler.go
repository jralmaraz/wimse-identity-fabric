package idp

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/caep"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/federation"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
)

// issueRequest is the JSON body for POST /wit/issue.
type issueRequest struct {
	Subject     string          `json:"subject"`
	TrustDomain string          `json:"trust_domain"`
	Audiences   []string        `json:"audiences"`
	PublicKey   json.RawMessage `json:"public_key"`
	KeyID       string          `json:"key_id"`
}

// issueResponse is the JSON response for POST /wit/issue.
type issueResponse struct {
	Token string `json:"token"`
}

// jwksResponse is the JSON response for GET /.well-known/jwks.json.
type jwksResponse struct {
	Keys []keys.JWK `json:"keys"`
}

// IssueHandler handles POST /wit/issue.
func IssueHandler(cfg *IdPConfig) gin.HandlerFunc {
	issuer := wit.NewIssuer(cfg.IssuerID, cfg.SigningKey.Private, cfg.TokenTTL)

	return func(c *gin.Context) {
		var req issueRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		if req.Subject == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "subject is required"})
			return
		}

		if len(req.PublicKey) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "public_key is required"})
			return
		}

		if !cfg.subjectAllowed(req.Subject) {
			c.JSON(http.StatusForbidden, gin.H{"error": "subject not allowed"})
			return
		}

		// Parse the workload's public key from JWK
		jwk, err := keys.JWKFromRawMessage(req.PublicKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public_key: " + err.Error()})
			return
		}
		workloadPub, err := keys.JWKToPublicKey(jwk)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public_key: " + err.Error()})
			return
		}

		trustDomain := req.TrustDomain
		if trustDomain == "" {
			trustDomain = cfg.TrustDomain
		}

		token, err := issuer.Issue(wit.IssueOptions{
			Subject:     req.Subject,
			TrustDomain: trustDomain,
			KeyID:       req.KeyID,
			Audiences:   req.Audiences,
			WorkloadKey: workloadPub,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
			return
		}

		if cfg.SSFTransmitter != nil {
			_ = cfg.SSFTransmitter.Emit(caep.EventTypeCredentialChange, caep.CredentialChangeEvent{
				Subject:        caep.NewSPIFFESubject(req.Subject),
				ChangeType:     "issue",
				EventTimestamp: time.Now().Unix(),
			})
		}

		c.JSON(http.StatusOK, issueResponse{Token: token})
	}
}

// JWKSHandler handles GET /.well-known/jwks.json.
func JWKSHandler(cfg *IdPConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		jwk, err := keys.PublicKeyToJWK(cfg.SigningKey.Public, "idp-key")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "key serialization failed"})
			return
		}
		c.JSON(http.StatusOK, jwksResponse{Keys: []keys.JWK{*jwk}})
	}
}

// EntityConfigHandler handles GET /.well-known/openid-federation.
// It serves a self-signed OID-FED Entity Configuration JWT for this IdP.
func EntityConfigHandler(cfg *IdPConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ttl := cfg.EntityConfigTTL
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		orgName := cfg.OrganizationName
		if orgName == "" {
			orgName = cfg.TrustDomain
		}
		ecJWT, err := federation.BuildEntityConfiguration(
			cfg.IssuerID,
			cfg.SigningKey.Private,
			"idp-key",
			orgName,
			cfg.AuthorityHints,
			ttl,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "entity configuration build failed"})
			return
		}
		// OID-FED §4 specifies Content-Type: application/entity-statement+jwt
		c.Header("Content-Type", "application/entity-statement+jwt")
		c.String(http.StatusOK, ecJWT)
	}
}

// revokeRequest is the JSON body for POST /wit/revoke.
type revokeRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason,omitempty"`
}

// RevokeHandler handles POST /wit/revoke.
// It emits a CAEP session-revoked event if an SSFTransmitter is configured.
// Callers are responsible for revoking any issued tokens through their own token-store;
// this handler only signals the event to SSF subscribers.
func RevokeHandler(cfg *IdPConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.SSFTransmitter == nil {
			c.JSON(http.StatusNotImplemented, gin.H{"error": "SSF transmitter not configured"})
			return
		}
		var req revokeRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.Subject == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "subject is required"})
			return
		}
		evt := caep.SessionRevokedEvent{
			Subject:        caep.NewSPIFFESubject(req.Subject),
			Reason:         req.Reason,
			EventTimestamp: time.Now().Unix(),
		}
		if err := cfg.SSFTransmitter.Emit(caep.EventTypeSessionRevoked, evt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to emit SSF event"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// ssfConfigResponse is the JSON body for GET /.well-known/ssf-configuration.
type ssfConfigResponse struct {
	Issuer                string   `json:"issuer"`
	JWKSUri               string   `json:"jwks_uri"`
	DeliveryMethodsSupported []string `json:"delivery_methods_supported"`
	EventTypesSupported   []string `json:"event_types_supported"`
}

// SSFConfigHandler handles GET /.well-known/ssf-configuration.
// Returns SSF transmitter metadata per OpenID SSF §7.
func SSFConfigHandler(cfg *IdPConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.SSFTransmitter == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "SSF not enabled"})
			return
		}
		meta := ssfConfigResponse{
			Issuer:  cfg.IssuerID,
			JWKSUri: cfg.IssuerID + "/.well-known/jwks.json",
			DeliveryMethodsSupported: []string{
				"https://schemas.openid.net/secevent/risc/delivery-method/push",
				"https://schemas.openid.net/secevent/risc/delivery-method/poll",
			},
			EventTypesSupported: []string{
				caep.EventTypeSessionRevoked,
				caep.EventTypeTokenClaimsChange,
				caep.EventTypeCredentialChange,
			},
		}
		c.JSON(http.StatusOK, meta)
	}
}

// FederationFetchHandler handles GET /federation/fetch?sub=<entityID>.
// When this IdP also acts as a Trust Anchor, it returns the Subordinate Statement
// it has signed for the given subject entity.
func FederationFetchHandler(cfg *IdPConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		sub := c.Query("sub")
		if sub == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "sub parameter required"})
			return
		}
		if cfg.TrustAnchorSubjects == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "this entity is not a trust anchor"})
			return
		}
		ssJWT, ok := cfg.TrustAnchorSubjects[sub]
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "no subordinate statement for subject"})
			return
		}
		c.Header("Content-Type", "application/entity-statement+jwt")
		c.String(http.StatusOK, ssJWT)
	}
}
