package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	commonauth "github.com/nusiss-capstone-project/identity-mservice/common/auth"
	"github.com/nusiss-capstone-project/identity-mservice/server/auth"
)

// AuthForward resolves a Clerk Bearer token into identity headers for Traefik ForwardAuth.
// Always returns 200; sets X-Internal-User-Id and X-User-Role only when authentication succeeds.
//
// @Summary Traefik ForwardAuth identity headers
// @Description Internal endpoint for Traefik ForwardAuth. Always returns HTTP 200 with an empty body. When Authorization Bearer JWT is valid, sets X-Internal-User-Id and X-User-Role response headers; otherwise leaves them unset.
// @Tags auth
// @Produce plain
// @Param Authorization header string false "Bearer Clerk JWT"
// @Success 200 {string} string "empty body; identity headers set only when authenticated"
// @Router /identity-ms/v1/auth/forward [get]
func AuthForward(c *gin.Context) {
	token, ok := bearerFromAuthorization(c.GetHeader("Authorization"))
	if !ok {
		c.Status(http.StatusOK)
		return
	}
	user, err := auth.NewAuthenticator().Authenticate(c.Request.Context(), token)
	if err != nil || user == nil {
		c.Status(http.StatusOK)
		return
	}
	c.Header(commonauth.HeaderInternalUserID, strconv.FormatInt(user.InternalUserID, 10))
	c.Header(commonauth.HeaderUserRole, user.Role)
	c.Status(http.StatusOK)
}

func bearerFromAuthorization(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}
