package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type fakeAuthenticator struct {
	user *User
	err  error
}

func (a fakeAuthenticator) Authenticate(context.Context, string) (*User, error) {
	if a.err != nil {
		return nil, a.err
	}
	return a.user, nil
}

func TestRequireUser_missingAuthorizationReturns401(t *testing.T) {
	rec := exerciseAuthMiddleware(t, requireRole("", fakeAuthenticator{
		user: &User{InternalUserID: 1, Role: RoleUser},
	}), "")

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), `"code":-1`)
	require.Contains(t, rec.Body.String(), "Authentication required")
}

func TestRequireUser_invalidTokenReturns401(t *testing.T) {
	rec := exerciseAuthMiddleware(t, requireRole("", fakeAuthenticator{
		err: errors.New("bad token"),
	}), "Bearer bad")

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), `"code":-1`)
	require.Contains(t, rec.Body.String(), "Authentication required")
}

func TestRequireUser_validUserCanAccess(t *testing.T) {
	rec := exerciseAuthMiddleware(t, requireRole("", fakeAuthenticator{
		user: &User{InternalUserID: 1, Role: RoleUser},
	}), "Bearer ok")

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAdmin_userRoleReturns403(t *testing.T) {
	rec := exerciseAuthMiddleware(t, requireRole(RoleAdmin, fakeAuthenticator{
		user: &User{InternalUserID: 1, Role: RoleUser},
	}), "Bearer ok")

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), `"code":-1`)
	require.Contains(t, rec.Body.String(), "Admin permission required")
}

func TestRequireAdmin_adminRoleCanAccess(t *testing.T) {
	rec := exerciseAuthMiddleware(t, requireRole(RoleAdmin, fakeAuthenticator{
		user: &User{InternalUserID: 1, Role: RoleAdmin},
	}), "Bearer ok")

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAdmin_devBypassAllowsLoopbackOnly(t *testing.T) {
	t.Setenv("APP_ENV", "local")
	t.Setenv("AUTH_DEV_BYPASS", "true")

	rec := exerciseAuthMiddlewareWithRemoteAddr(t, requireRole(RoleAdmin, fakeAuthenticator{
		err: errors.New("should not verify token"),
	}), "", "127.0.0.1:12345")

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAdmin_devBypassRejectsNonLoopback(t *testing.T) {
	t.Setenv("APP_ENV", "local")
	t.Setenv("AUTH_DEV_BYPASS", "true")

	rec := exerciseAuthMiddlewareWithRemoteAddr(t, requireRole(RoleAdmin, fakeAuthenticator{
		err: errors.New("bad token"),
	}), "", "203.0.113.10:12345")

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), `"code":-1`)
}

func TestRequireAdmin_devBypassRejectsSpoofedForwardedFor(t *testing.T) {
	t.Setenv("APP_ENV", "local")
	t.Setenv("AUTH_DEV_BYPASS", "true")

	rec := exerciseAuthMiddlewareWithRequest(t, requireRole(RoleAdmin, fakeAuthenticator{
		err: errors.New("bad token"),
	}), "", "203.0.113.10:12345", map[string]string{
		"X-Forwarded-For": "127.0.0.1",
	})

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), `"code":-1`)
}

func exerciseAuthMiddleware(t *testing.T, mw gin.HandlerFunc, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("APP_ENV", "test")
	t.Setenv("AUTH_DEV_BYPASS", "")
	return exerciseAuthMiddlewareWithRemoteAddr(t, mw, authorization, "192.0.2.1:12345")
}

func exerciseAuthMiddlewareWithRemoteAddr(
	t *testing.T,
	mw gin.HandlerFunc,
	authorization string,
	remoteAddr string,
) *httptest.ResponseRecorder {
	return exerciseAuthMiddlewareWithRequest(t, mw, authorization, remoteAddr, nil)
}

func exerciseAuthMiddlewareWithRequest(
	t *testing.T,
	mw gin.HandlerFunc,
	authorization string,
	remoteAddr string,
	headers map[string]string,
) *httptest.ResponseRecorder {
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
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}
