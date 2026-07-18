package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMemoryKYCStateStore_consumeReturnsPending(t *testing.T) {
	store := newMemoryKYCStateStore(time.Minute)
	store.Save("abc", KYCPending{InternalUserID: 7, Email: "a@example.com"})

	got, ok := store.Consume("abc")
	require.True(t, ok)
	require.Equal(t, int64(7), got.InternalUserID)
	require.Equal(t, "a@example.com", got.Email)

	_, ok = store.Consume("abc")
	require.False(t, ok)
}

func TestMemoryKYCStateStore_expiredStateRejected(t *testing.T) {
	store := newMemoryKYCStateStore(time.Minute)
	fixed := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }
	store.Save("abc", KYCPending{InternalUserID: 1, Email: "a@example.com"})

	store.now = func() time.Time { return fixed.Add(2 * time.Minute) }
	_, ok := store.Consume("abc")
	require.False(t, ok)
}

func TestMemoryKYCStateStore_ignoresEmptyState(t *testing.T) {
	store := newMemoryKYCStateStore(time.Minute)
	store.Save("", KYCPending{InternalUserID: 1, Email: "a@example.com"})

	_, ok := store.Consume("")
	require.False(t, ok)
}

func TestMemoryKYCStateStore_defaultTTLWhenNonPositive(t *testing.T) {
	store := newMemoryKYCStateStore(0)
	require.Equal(t, defaultKYCStateTTL, store.ttl)

	fixed := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }
	store.Save("abc", KYCPending{InternalUserID: 1})

	store.now = func() time.Time { return fixed.Add(defaultKYCStateTTL - time.Second) }
	_, ok := store.Consume("abc")
	require.True(t, ok)

	store.now = func() time.Time { return fixed }
	store.Save("def", KYCPending{InternalUserID: 2})
	store.now = func() time.Time { return fixed.Add(defaultKYCStateTTL + time.Second) }
	_, ok = store.Consume("def")
	require.False(t, ok)
}

func TestMemoryKYCStateStore_purgeRemovesOtherExpiredEntries(t *testing.T) {
	store := newMemoryKYCStateStore(time.Minute)
	fixed := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }
	store.Save("old", KYCPending{InternalUserID: 1})
	store.Save("fresh", KYCPending{InternalUserID: 2})

	store.now = func() time.Time { return fixed.Add(2 * time.Minute) }
	store.Save("newer", KYCPending{InternalUserID: 3})

	_, ok := store.Consume("old")
	require.False(t, ok)
	got, ok := store.Consume("newer")
	require.True(t, ok)
	require.Equal(t, int64(3), got.InternalUserID)
}
