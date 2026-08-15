package service

import (
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
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
		log.Logger.Warnw("kyc state save skipped: empty state")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if pending.ExpiresAt.IsZero() {
		pending.ExpiresAt = s.now().Add(s.ttl)
	}
	s.items[state] = pending
	s.purgeExpiredLocked()
	log.Logger.Infow("kyc state saved",
		"user_id", pending.InternalUserID,
		"state_len", len(state),
		"state_prefix", trimStatePrefix(state),
		"expires_at", pending.ExpiresAt.UTC().Format(time.RFC3339),
		"store_size", len(s.items),
	)
}

func (s *memoryKYCStateStore) Consume(state string) (KYCPending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	pending, ok := s.items[state]
	if !ok {
		prefixes := make([]string, 0, len(s.items))
		for k := range s.items {
			prefixes = append(prefixes, trimStatePrefix(k))
			if len(prefixes) >= 10 {
				break
			}
		}
		log.Logger.Warnw("kyc state consume miss",
			"state_len", len(state),
			"state_prefix", trimStatePrefix(state),
			"store_size", len(s.items),
			"known_state_prefixes", prefixes,
			"reason", "not_found_or_already_consumed_or_other_instance",
		)
		return KYCPending{}, false
	}
	delete(s.items, state)
	if s.now().After(pending.ExpiresAt) {
		log.Logger.Warnw("kyc state consume expired",
			"user_id", pending.InternalUserID,
			"state_prefix", trimStatePrefix(state),
			"expires_at", pending.ExpiresAt.UTC().Format(time.RFC3339),
			"store_size", len(s.items),
			"reason", "expired",
		)
		return KYCPending{}, false
	}
	log.Logger.Infow("kyc state consume ok",
		"user_id", pending.InternalUserID,
		"state_prefix", trimStatePrefix(state),
		"store_size", len(s.items),
	)
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
