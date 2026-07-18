package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type requestAuthenticator interface {
	Authenticate(ctx context.Context, token string) (*User, error)
}

func RequireUser() gin.HandlerFunc {
	return requireRole("", NewAuthenticator())
}

func RequireAdmin() gin.HandlerFunc {
	return requireRole(RoleAdmin, NewAuthenticator())
}

func requireRole(role string, authenticator requestAuthenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := authenticateRequest(c, authenticator)
		if !ok {
			return
		}
		if role == RoleAdmin && user.Role != RoleAdmin {
			forbidden(c)
			return
		}
		ctx := WithUser(c.Request.Context(), user)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func authenticateRequest(c *gin.Context, authenticator requestAuthenticator) (*User, bool) {
	if devBypassEnabled() && devBypassAllowedRemoteAddr(c.Request.RemoteAddr) {
		return devBypassUser(), true
	}
	token, ok := bearerToken(c.GetHeader("Authorization"))
	if !ok {
		unauthorized(c)
		return nil, false
	}
	user, err := authenticator.Authenticate(c.Request.Context(), token)
	if err != nil {
		unauthorized(c)
		return nil, false
	}
	return user, true
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func unauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"code":    -1,
		"data":    nil,
		"message": "Authentication required",
	})
}

func forbidden(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"code":    -1,
		"data":    nil,
		"message": "Admin permission required",
	})
}
