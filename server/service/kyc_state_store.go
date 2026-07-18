package service

import (
	"sync"
	"time"
)

const defaultKYCStateTTL = 10 * time.Minute

// KYCPending binds an OAuth state to the authenticated user who started KYC.
type KYCPending struct {
	InternalUserID int64
	Email          string
	ExpiresAt      time.Time
}

// KYCStateStore stores pending Singpass KYC attempts keyed by OAuth state.
type KYCStateStore interface {
	Save(state string, pending KYCPending)
	// Consume returns and deletes a non-expired pending session.
	Consume(state string) (KYCPending, bool)
}

type memoryKYCStateStore struct {
	mu    sync.Mutex
	items map[string]KYCPending
	ttl   time.Duration
	now   func() time.Time
}

func newMemoryKYCStateStore(ttl time.Duration) *memoryKYCStateStore {
	if ttl <= 0 {
		ttl = defaultKYCStateTTL
	}
	return &memoryKYCStateStore{
		items: make(map[string]KYCPending),
		ttl:   ttl,
		now:   time.Now,
	}
}

func (s *memoryKYCStateStore) Save(state string, pending KYCPending) {
	if state == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if pending.ExpiresAt.IsZero() {
		pending.ExpiresAt = s.now().Add(s.ttl)
	}
	s.items[state] = pending
	s.purgeExpiredLocked()
}

func (s *memoryKYCStateStore) Consume(state string) (KYCPending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	pending, ok := s.items[state]
	if !ok {
		return KYCPending{}, false
	}
	delete(s.items, state)
	if s.now().After(pending.ExpiresAt) {
		return KYCPending{}, false
	}
	return pending, true
}

func (s *memoryKYCStateStore) purgeExpiredLocked() {
	now := s.now()
	for k, v := range s.items {
		if now.After(v.ExpiresAt) {
			delete(s.items, k)
		}
	}
}

var (
	kycStateStoreOnce sync.Once
	kycStateStoreInst KYCStateStore
)

func GetKYCStateStore() KYCStateStore {
	kycStateStoreOnce.Do(func() {
		kycStateStoreInst = newMemoryKYCStateStore(defaultKYCStateTTL)
	})
	return kycStateStoreInst
}
