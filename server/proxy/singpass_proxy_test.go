package proxy

import (
	"testing"

	"github.com/nusiss-capstone-project/identity-mservice/server/config"
	"github.com/stretchr/testify/require"
)

func TestResolveAssertionAud_prefersExplicit(t *testing.T) {
	aud := resolveAssertionAud(&config.SingpassConfig{
		IssuerURL:    "https://public.example/singpass/v2",
		AssertionAud: "http://mockpass.svc/singpass/v2",
		TokenURL:     "http://mockpass.svc/singpass/v2/token",
	})
	require.Equal(t, "http://mockpass.svc/singpass/v2", aud)
}

func TestResolveAssertionAud_derivesFromTokenURL(t *testing.T) {
	aud := resolveAssertionAud(&config.SingpassConfig{
		IssuerURL: "https://public.example/mockpass/singpass/v2",
		TokenURL:  "http://mockpass.mockpass.svc.cluster.local:5156/singpass/v2/token",
	})
	require.Equal(t, "http://mockpass.mockpass.svc.cluster.local:5156/singpass/v2", aud)
}

func TestResolveAssertionAud_fallsBackToIssuer(t *testing.T) {
	aud := resolveAssertionAud(&config.SingpassConfig{
		IssuerURL: "https://public.example/singpass/v2/",
		TokenURL:  "https://other.example/oauth/token-endpoint",
	})
	require.Equal(t, "https://public.example/singpass/v2", aud)
}
