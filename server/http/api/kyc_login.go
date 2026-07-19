package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nusiss-capstone-project/identity-mservice/server/auth"
	"github.com/nusiss-capstone-project/identity-mservice/server/config"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/service"
)

// SingpassLoginData is returned to the authenticated client to start Singpass KYC.
type SingpassLoginData struct {
	AuthorizeURL string `json:"authorizeUrl"`
}

// SingpassLogin returns the Singpass authorize URL bound to the authenticated user via OAuth state.
// @Summary Start Singpass KYC
// @Description Requires authentication. Returns an authorize URL; the client should redirect the browser to it.
// @Tags singpass
// @Produce json
// @Success 200 {object} data.BaseResponse "authorize url"
// @Failure 401 {object} data.BaseResponse "authentication required"
// @Router /identity-ms/v1/web/kyc/singpass/login [get]
func SingpassLogin(c *gin.Context) {
	user, ok := auth.GetUser(c.Request.Context())
	if !ok {
		authError(c)
		return
	}
	authorizeURL, err := service.GetKYCService().StartSingpassLogin(c.Request.Context(), user.InternalUserID, user.Email)
	if err != nil {
		data.JSON(c, http.StatusInternalServerError, -1, "failed to start singpass login", nil)
		return
	}
	data.OK(c, SingpassLoginData{AuthorizeURL: authorizeURL})
}

// SingpassCallback handles Singpass callback.
// @Summary Singpass callback
// @Description Validates OAuth state and completes KYC for the user who started login, then redirects to post_kyc_redirect_uri.
// @Tags singpass
// @Param code query string true "Singpass code"
// @Param state query string true "OAuth state"
// @Success 302 "redirect to post_kyc_redirect_uri"
// @Failure 400 {object} data.BaseResponse "invalid code or state"
// @Router /identity-ms/v1/kyc/singpass/callback [get]
func SingpassCallback(c *gin.Context) {
	log.WithContext(c.Request.Context()).Infow("singpass callback received")

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}
	state := c.Query("state")
	if state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
		return
	}
	err := service.GetKYCService().SingpassCallback(c.Request.Context(), code, state)
	if err != nil {
		if errors.Is(err, service.ErrInvalidOAuthState) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired state"})
			return
		}
		if errors.Is(err, service.ErrKYCEmailMismatch) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Singpass email does not match authenticated user"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	redirectURI := ""
	if config.Config != nil && config.Config.SystemConfig != nil {
		redirectURI = strings.TrimSpace(config.Config.SystemConfig.PostKYCRedirectURI)
	}
	if redirectURI == "" {
		c.JSON(http.StatusOK, gin.H{"message": "Callback accepted"})
		return
	}
	c.Redirect(http.StatusFound, redirectURI)
}
