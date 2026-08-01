package auth

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequireUser authenticates via Traefik-forwarded identity headers (no role check).
func RequireUser() gin.HandlerFunc {
	return RequireRole(nil)
}

// RequireAdmin authenticates via headers and requires the admin role.
func RequireAdmin() gin.HandlerFunc {
	return RequireRole([]string{RoleAdmin})
}

// RequireRole authenticates via identity headers. When roles is empty, only authentication
// is required; otherwise the caller's role must be one of the listed values.
func RequireRole(roles []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		allowed[role] = struct{}{}
	}
	return func(c *gin.Context) {
		user, ok := userFromHeaders(c)
		if !ok {
			unauthorized(c)
			return
		}
		if len(allowed) > 0 {
			if _, ok := allowed[user.Role]; !ok {
				forbidden(c)
				return
			}
		}
		ctx := WithUser(c.Request.Context(), user)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func userFromHeaders(c *gin.Context) (*User, bool) {
	rawID := strings.TrimSpace(c.GetHeader(HeaderInternalUserID))
	role := strings.TrimSpace(c.GetHeader(HeaderUserRole))
	if rawID == "" || role == "" {
		return nil, false
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		return nil, false
	}
	return &User{
		InternalUserID: id,
		Role:           role,
	}, true
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
		"message": "Permission required",
	})
}

// RequireInternalNetwork allows only loopback/private clients, or any client when APP_ENV=local.
func RequireInternalNetwork() gin.HandlerFunc {
	return func(c *gin.Context) {
		if internalNetworkOpen() || isInternalRemoteAddr(c.Request.RemoteAddr) {
			c.Next()
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
	}
}

func internalNetworkOpen() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "local")
}

func isInternalRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
