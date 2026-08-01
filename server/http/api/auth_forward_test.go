package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	commonauth "github.com/nusiss-capstone-project/identity-mservice/common/auth"
)

func TestAuthForward_missingTokenReturns200WithoutHeaders(t *testing.T) {
	rec := exerciseAuthForward(t, "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, rec.Header().Get(commonauth.HeaderInternalUserID))
	require.Empty(t, rec.Header().Get(commonauth.HeaderUserRole))
}

func TestAuthForward_invalidTokenReturns200WithoutHeaders(t *testing.T) {
	t.Setenv("CLERK_JWKS_URL", "")
	t.Setenv("CLERK_ISSUER", "")
	rec := exerciseAuthForward(t, "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.e30.sig")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, rec.Header().Get(commonauth.HeaderInternalUserID))
	require.Empty(t, rec.Header().Get(commonauth.HeaderUserRole))
}

func exerciseAuthForward(t *testing.T, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/auth/forward", AuthForward)
	req := httptest.NewRequest(http.MethodGet, "/auth/forward", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}
