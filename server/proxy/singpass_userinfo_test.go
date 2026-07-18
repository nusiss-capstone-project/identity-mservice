package proxy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSingpassClaimValue_myinfoObject(t *testing.T) {
	raw := json.RawMessage(`{
		"lastupdated": "2023-03-23",
		"source": "1",
		"classification": "C",
		"value": "USER S8979373D"
	}`)
	require.Equal(t, "USER S8979373D", parseSingpassClaimValue(raw))
}

func TestMapSingpassClaimsToUserInfo(t *testing.T) {
	claims := []byte(`{
		"sub": "s=S8979373D,u=uuid",
		"name": {"value": "USER S8979373D"},
		"email": {"value": "demo@example.com"},
		"mobileno": {"value": "91234567"}
	}`)

	userInfo := mapSingpassClaimsToUserInfo(claims)

	require.Equal(t, "USER S8979373D", userInfo.Name)
	require.Equal(t, "demo@example.com", userInfo.Email)
	require.Equal(t, "91234567", userInfo.Phone)
}
