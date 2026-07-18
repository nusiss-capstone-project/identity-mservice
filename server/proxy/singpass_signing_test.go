package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadClientJWKSRaw_requiresConfig(t *testing.T) {
	t.Setenv("SINGPASS_CLIENT_JWKS_URI", "")
	t.Setenv("SINGPASS_CLIENT_JWKS", "")

	_, err := loadClientJWKSRaw(http.DefaultClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "SINGPASS_CLIENT_JWKS")
}

func TestLoadClientJWKSRaw_fromEnvJSON(t *testing.T) {
	t.Setenv("SINGPASS_CLIENT_JWKS_URI", "")
	t.Setenv("SINGPASS_CLIENT_JWKS", `{"keys":[]}`)

	raw, err := loadClientJWKSRaw(http.DefaultClient)
	require.NoError(t, err)
	require.Equal(t, `{"keys":[]}`, string(raw))
}

func TestLoadClientJWKSRaw_fromURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"use":"sig"}]}`))
	}))
	t.Cleanup(srv.Close)

	t.Setenv("SINGPASS_CLIENT_JWKS_URI", srv.URL)
	t.Setenv("SINGPASS_CLIENT_JWKS", "")

	raw, err := loadClientJWKSRaw(srv.Client())
	require.NoError(t, err)
	require.Contains(t, string(raw), `"use":"sig"`)
}
