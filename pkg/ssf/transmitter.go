package ssf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SET is a Security Event Token (RFC 8417).
type SET struct {
	JTI      string         `json:"jti"`
	Issuer   string         `json:"iss"`
	IssuedAt int64          `json:"iat"`
	Audience []string       `json:"aud,omitempty"`
	Events   map[string]any `json:"events"`
}

// StreamConfig configures a single SSF delivery stream.
type StreamConfig struct {
	ID              string
	DeliveryMethod  string // "https://schemas.openid.net/secevent/risc/delivery-method/push"
	EndpointURL     string // push endpoint; empty for poll-only
	EventTypes      []string
	Audiences       []string
}

// setClaims is the JWT claims structure for a signed SET.
type setClaims struct {
	jwt.RegisteredClaims
	Events map[string]any `json:"events"`
}

// Transmitter is a minimal SSF event transmitter (OpenID SSF §5).
// It signs SETs as secevent+jwt and delivers them via push webhook or in-process channel.
type Transmitter struct {
	issuerID string
	sigKey   *ecdsa.PrivateKey
	client   *http.Client

	mu      sync.RWMutex
	streams map[string]*StreamConfig
	ch      chan SET
}

// NewTransmitter creates a Transmitter that signs SETs with the given EC private key.
func NewTransmitter(issuerID string, sigKey *ecdsa.PrivateKey) *Transmitter {
	return &Transmitter{
		issuerID: issuerID,
		sigKey:   sigKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
			},
		},
		streams: make(map[string]*StreamConfig),
		ch:      make(chan SET, 64),
	}
}

// RegisterStream adds a delivery stream. If cfg.ID is empty, a UUID is generated.
func (t *Transmitter) RegisterStream(cfg StreamConfig) string {
	if cfg.ID == "" {
		cfg.ID = newID()
	}
	t.mu.Lock()
	t.streams[cfg.ID] = &cfg
	t.mu.Unlock()
	return cfg.ID
}

// DeregisterStream removes a stream by ID.
func (t *Transmitter) DeregisterStream(streamID string) {
	t.mu.Lock()
	delete(t.streams, streamID)
	t.mu.Unlock()
}

// Subscribe returns the channel that receives in-process SETs.
// All streams share the same channel; receivers filter by event type as needed.
func (t *Transmitter) Subscribe() <-chan SET {
	return t.ch
}

// Emit signs and dispatches a SET for the given event type.
// payload must be JSON-marshalable; it becomes the value in the "events" map.
func (t *Transmitter) Emit(eventType string, payload any) error {
	now := time.Now()
	jti := newID()

	payloadRaw, err := toMap(payload)
	if err != nil {
		return fmt.Errorf("ssf: marshal event payload: %w", err)
	}

	set := SET{
		JTI:      jti,
		Issuer:   t.issuerID,
		IssuedAt: now.Unix(),
		Events:   map[string]any{eventType: payloadRaw},
	}

	// collect audiences from all matching streams
	t.mu.RLock()
	var matchingStreams []*StreamConfig
	for _, s := range t.streams {
		if streamWantsEvent(s, eventType) {
			matchingStreams = append(matchingStreams, s)
		}
	}
	t.mu.RUnlock()

	// build union of audiences
	audSet := map[string]struct{}{}
	for _, s := range matchingStreams {
		for _, a := range s.Audiences {
			audSet[a] = struct{}{}
		}
	}
	for a := range audSet {
		set.Audience = append(set.Audience, a)
	}

	// sign
	compact, err := t.sign(set)
	if err != nil {
		return fmt.Errorf("ssf: sign SET: %w", err)
	}

	// non-blocking in-process delivery
	select {
	case t.ch <- set:
	default:
	}

	// async push delivery
	for _, s := range matchingStreams {
		if s.EndpointURL != "" {
			go t.push(s.EndpointURL, compact)
		}
	}
	return nil
}

func (t *Transmitter) sign(set SET) (string, error) {
	claims := setClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       set.JTI,
			Issuer:   set.Issuer,
			IssuedAt: jwt.NewNumericDate(time.Unix(set.IssuedAt, 0)),
			Audience: set.Audience,
		},
		Events: set.Events,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "secevent+jwt"
	return tok.SignedString(t.sigKey)
}

func (t *Transmitter) push(endpoint, compact string) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader([]byte(compact)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	resp, err := t.client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// ParseSET verifies a compact SET JWT signed with the given EC public key.
func ParseSET(compact string, pub *ecdsa.PublicKey) (*SET, error) {
	var claims setClaims
	tok, err := jwt.ParseWithClaims(compact, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		if typ, _ := t.Header["typ"].(string); typ != "secevent+jwt" {
			return nil, fmt.Errorf("unexpected typ: %s", typ)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("ssf: invalid SET: %w", err)
	}
	aud, _ := claims.GetAudience()
	return &SET{
		JTI:      claims.ID,
		Issuer:   claims.Issuer,
		IssuedAt: claims.IssuedAt.Unix(),
		Audience: aud,
		Events:   claims.Events,
	}, nil
}

func streamWantsEvent(s *StreamConfig, eventType string) bool {
	if len(s.EventTypes) == 0 {
		return true
	}
	for _, et := range s.EventTypes {
		if et == eventType {
			return true
		}
	}
	return false
}

// newID returns a random 16-byte hex string.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("ssf: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// toMap round-trips a value through JSON to produce map[string]any.
func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
