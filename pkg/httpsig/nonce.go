package httpsig

import (
	"errors"
	"sync"
	"time"
)

// ErrNonceReplayed is returned when a nonce has already been seen.
var ErrNonceReplayed = errors.New("nonce already seen (replay attack)")

// NonceStore records request nonces to prevent replay attacks.
type NonceStore interface {
	Record(nonce string, exp time.Time) error
}

// InMemoryNonceStore is the default single-process nonce store. It sweeps
// expired entries on each Record call, bounding memory to nonces within their
// validity window.
type InMemoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewInMemoryNonceStore creates a new InMemoryNonceStore.
func NewInMemoryNonceStore() *InMemoryNonceStore {
	return &InMemoryNonceStore{seen: make(map[string]time.Time)}
}

// Record records a nonce and returns ErrNonceReplayed if already seen.
func (s *InMemoryNonceStore) Record(nonce string, exp time.Time) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, expiry := range s.seen {
		if now.After(expiry) {
			delete(s.seen, n)
		}
	}
	if _, replayed := s.seen[nonce]; replayed {
		return ErrNonceReplayed
	}
	s.seen[nonce] = exp
	return nil
}
