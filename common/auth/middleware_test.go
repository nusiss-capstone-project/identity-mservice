package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRequireUser_missingHeadersReturns401(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireUser(), nil, "192.0.2.1:12345")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "Authentication required")
}

func TestRequireUser_invalidUserIDReturns401(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireUser(), map[string]string{
		HeaderInternalUserID: "abc",
		HeaderUserRole:       RoleUser,
	}, "192.0.2.1:12345")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireUser_requiresUserRole(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireUser(), map[string]string{
		HeaderInternalUserID: "42",
		HeaderUserRole:       RoleUser,
	}, "192.0.2.1:12345")
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireUser_rejectsAdminRole(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireUser(), map[string]string{
		HeaderInternalUserID: "1",
		HeaderUserRole:       RoleAdmin,
	}, "192.0.2.1:12345")
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireAdmin_userRoleReturns403(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireAdmin(), map[string]string{
		HeaderInternalUserID: "42",
		HeaderUserRole:       RoleUser,
	}, "192.0.2.1:12345")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "Permission required")
}

func TestRequireAdmin_adminRoleCanAccess(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireAdmin(), map[string]string{
		HeaderInternalUserID: "1",
		HeaderUserRole:       RoleAdmin,
	}, "192.0.2.1:12345")
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_emptyMeansAuthenticateOnly(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireRole(nil), nil, "192.0.2.1:12345")
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	rec = exerciseHeaderAuth(t, RequireRole(nil), map[string]string{
		HeaderInternalUserID: "7",
		HeaderUserRole:       RoleCampaignOps,
	}, "192.0.2.1:12345")
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestPermitAll_allowsMissingHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PermitAll())
	r.GET("/x", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_allowsListedRole(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireRole([]string{RoleFinanceAdmin, RoleCampaignOps}), map[string]string{
		HeaderInternalUserID: "7",
		HeaderUserRole:       RoleFinanceAdmin,
	}, "192.0.2.1:12345")
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_rejectsUnlistedRole(t *testing.T) {
	rec := exerciseHeaderAuth(t, RequireRole([]string{RoleFinanceAdmin}), map[string]string{
		HeaderInternalUserID: "7",
		HeaderUserRole:       RoleUser,
	}, "192.0.2.1:12345")
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireInternalNetwork_allowsPrivateIP(t *testing.T) {
	t.Setenv("APP_ENV", "prod")
	rec := exerciseInternalGuard(t, "10.0.0.5:12345")
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireInternalNetwork_allowsLoopback(t *testing.T) {
	t.Setenv("APP_ENV", "prod")
	rec := exerciseInternalGuard(t, "127.0.0.1:12345")
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireInternalNetwork_rejectsPublicIP(t *testing.T) {
	t.Setenv("APP_ENV", "prod")
	rec := exerciseInternalGuard(t, "203.0.113.10:12345")
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireInternalNetwork_localEnvAllowsPublicIP(t *testing.T) {
	t.Setenv("APP_ENV", "local")
	rec := exerciseInternalGuard(t, "203.0.113.10:12345")
	require.Equal(t, http.StatusOK, rec.Code)
}

func exerciseHeaderAuth(t *testing.T, mw gin.HandlerFunc, headers map[string]string, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(mw)
	r.GET("/x", func(c *gin.Context) {
		if _, ok := GetUserID(c.Request.Context()); !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func exerciseInternalGuard(t *testing.T, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireInternalNetwork())
	r.GET("/x", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}
