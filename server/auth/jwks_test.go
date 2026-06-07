package auth

import (
	"crypto/rsa"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJWKSCachePublicKey_cacheHitReturnsKey(t *testing.T) {
	expected := &rsa.PublicKey{N: big.NewInt(17), E: 65537}
	cache := &jwksCache{
		url:       "://invalid",
		expiresAt: time.Now().Add(time.Minute),
		keys:      map[string]*rsa.PublicKey{"known": expected},
	}

	key, err := cache.publicKey("known")

	require.NoError(t, err)
	require.Same(t, expected, key)
}

func TestJWKSCachePublicKey_cacheMissWithinTTLDoesNotRefresh(t *testing.T) {
	cache := &jwksCache{
		url:       "://invalid",
		expiresAt: time.Now().Add(time.Minute),
		keys:      map[string]*rsa.PublicKey{},
	}

	key, err := cache.publicKey("random-kid")

	require.Nil(t, key)
	require.EqualError(t, err, "clerk jwks key not found")
}
