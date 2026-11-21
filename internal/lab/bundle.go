package lab

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
)

// TrustBundle maps trust domains to their issuer and signing keys.
//
// Per draft-ietf-wimse-workload-creds §4, a validator selects trust anchors
// from the trust domain in the WIT's `sub` – configured out of band – and
// never discovers keys from the token's `iss`. Listing a foreign trust domain
// here IS the federation decision.
//
// Format of TRUST_DOMAINS (issuer base URL doubles as the issuer ID / iss):
//
//	aws.wimse.local=http://issuer-aws:8080,gcp.wimse.local=http://issuer-gcp:8080
type TrustBundle struct {
	issuers map[string]string // trust domain -> issuer ID (base URL)
	ttl     time.Duration
	client  *http.Client

	mu    sync.Mutex
	cache map[string]cachedKeys
}

type cachedKeys struct {
	at   time.Time
	keys []*ecdsa.PublicKey
}

// NewTrustBundle builds a bundle from a domain -> issuer URL map.
func NewTrustBundle(issuers map[string]string) *TrustBundle {
	m := make(map[string]string, len(issuers))
	for d, u := range issuers {
		m[strings.ToLower(d)] = strings.TrimRight(u, "/")
	}
	return &TrustBundle{issuers: m, ttl: 5 * time.Minute, client: &http.Client{Timeout: 5 * time.Second},
		cache: map[string]cachedKeys{}}
}

// ParseTrustDomains parses the TRUST_DOMAINS format.
func ParseTrustDomains(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		domain, issuer, ok := strings.Cut(item, "=")
		if !ok || domain == "" || issuer == "" {
			return nil, fmt.Errorf("bad TRUST_DOMAINS entry %q (want domain=issuerURL)", item)
		}
		out[strings.TrimSpace(domain)] = strings.TrimSpace(issuer)
	}
	return out, nil
}

// TrustBundleFromEnv reads TRUST_DOMAINS.
func TrustBundleFromEnv() (*TrustBundle, error) {
	m, err := ParseTrustDomains(os.Getenv("TRUST_DOMAINS"))
	if err != nil {
		return nil, err
	}
	return NewTrustBundle(m), nil
}

// Domains lists the federated trust domains.
func (b *TrustBundle) Domains() []string {
	out := make([]string, 0, len(b.issuers))
	for d := range b.issuers {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Issuer returns the issuer ID configured for a trust domain.
func (b *TrustBundle) Issuer(domain string) (string, bool) {
	iss, ok := b.issuers[strings.ToLower(domain)]
	return iss, ok
}

// DomainOfIssuer finds the trust domain whose configured issuer is iss.
func (b *TrustBundle) DomainOfIssuer(iss string) (string, bool) {
	iss = strings.TrimRight(iss, "/")
	for d, i := range b.issuers {
		if i == iss {
			return d, true
		}
	}
	return "", false
}

// Keys returns the signing keys of a trust domain, fetching its JWKS when the
// cache is cold. refresh forces a re-fetch (key rotation).
func (b *TrustBundle) Keys(domain string, refresh bool) ([]*ecdsa.PublicKey, error) {
	domain = strings.ToLower(domain)
	iss, ok := b.issuers[domain]
	if !ok {
		return nil, fmt.Errorf("trust domain %q is not federated", domain)
	}
	b.mu.Lock()
	c, hit := b.cache[domain]
	b.mu.Unlock()
	if hit && !refresh && time.Since(c.at) < b.ttl {
		return c.keys, nil
	}
	resp, err := b.client.Get(iss + "/.well-known/jwks.json")
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS for %s: %w", domain, err)
	}
	defer resp.Body.Close()
	var body struct {
		Keys []keys.JWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode JWKS for %s: %w", domain, err)
	}
	var pubs []*ecdsa.PublicKey
	for i := range body.Keys {
		if pub, err := keys.JWKToPublicKey(&body.Keys[i]); err == nil {
			pubs = append(pubs, pub)
		}
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("JWKS for %s has no usable EC keys", domain)
	}
	b.mu.Lock()
	b.cache[domain] = cachedKeys{at: time.Now(), keys: pubs}
	b.mu.Unlock()
	return pubs, nil
}

// TrustDomainOf validates a Workload Identifier (spiffe:// or wimse:// URI)
// and returns its trust domain (the URI authority).
func TrustDomainOf(workloadID string) (string, error) {
	u, err := url.Parse(workloadID)
	if err != nil {
		return "", err
	}
	if u.Scheme != "spiffe" && u.Scheme != "wimse" {
		return "", fmt.Errorf("scheme %q not allowed (spiffe or wimse)", u.Scheme)
	}
	if u.Host == "" || u.User != nil || u.Port() != "" {
		return "", errors.New("authority must be a bare trust domain")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("workload identifier must not carry a query or fragment")
	}
	if u.Path == "" || u.Path == "/" {
		return "", errors.New("workload identifier needs a path inside the trust domain")
	}
	return strings.ToLower(u.Host), nil
}

// ShortName turns spiffe://aws.wimse.local/ns/shop/sa/orders into "orders".
func ShortName(workloadID string) string {
	if workloadID == "" {
		return "unknown"
	}
	parts := strings.Split(strings.TrimRight(workloadID, "/"), "/")
	return parts[len(parts)-1]
}
