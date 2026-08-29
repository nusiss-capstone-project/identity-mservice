package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	commonauth "github.com/nusiss-capstone-project/identity-mservice/common/auth"
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
	user, ok := commonauth.GetUser(c.Request.Context())
	if !ok {
		authError(c)
		return
	}
	authorizeURL, err := service.GetKYCService().StartSingpassLogin(c.Request.Context(), user.InternalUserID, user.Email)
	if err != nil {
		log.WithContext(c.Request.Context()).Errorw("singpass login start failed",
			"user_id", user.InternalUserID, "error", err)
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
	ctx := c.Request.Context()
	code := c.Query("code")
	state := c.Query("state")
	idpError := c.Query("error")
	idpErrorDesc := c.Query("error_description")

	log.WithContext(ctx).Infow("singpass callback received",
		"has_code", code != "",
		"code_len", len(code),
		"has_state", state != "",
		"state_len", len(state),
		"state_prefix", trimPrefix(state, 8),
		"idp_error", idpError,
		"idp_error_description", idpErrorDesc,
		"client_ip", c.ClientIP(),
		"user_agent", c.Request.UserAgent(),
		"referer", c.Request.Referer(),
	)

	if idpError != "" {
		log.WithContext(ctx).Warnw("singpass callback rejected: idp error",
			"reason", "idp_error",
			"http_status", http.StatusBadRequest,
			"idp_error", idpError,
			"idp_error_description", idpErrorDesc,
			"state_prefix", trimPrefix(state, 8),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":                 "singpass authorization failed",
			"idp_error":             idpError,
			"idp_error_description": idpErrorDesc,
		})
		return
	}
	if code == "" {
		log.WithContext(ctx).Warnw("singpass callback rejected: missing code",
			"reason", "missing_code",
			"http_status", http.StatusBadRequest,
			"has_state", state != "",
			"state_prefix", trimPrefix(state, 8),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}
	if state == "" {
		log.WithContext(ctx).Warnw("singpass callback rejected: missing state",
			"reason", "missing_state",
			"http_status", http.StatusBadRequest,
			"has_code", code != "",
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
		return
	}

	err := service.GetKYCService().SingpassCallback(ctx, code, state)
	if err != nil {
		if errors.Is(err, service.ErrInvalidOAuthState) {
			log.WithContext(ctx).Warnw("singpass callback rejected: invalid or expired state",
				"reason", "invalid_or_expired_state",
				"http_status", http.StatusBadRequest,
				"state_len", len(state),
				"state_prefix", trimPrefix(state, 8),
				"error", err,
			)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired state"})
			return
		}
		if errors.Is(err, service.ErrKYCEmailMismatch) {
			log.WithContext(ctx).Warnw("singpass callback rejected: email mismatch",
				"reason", "email_mismatch",
				"http_status", http.StatusForbidden,
				"state_prefix", trimPrefix(state, 8),
				"error", err,
			)
			c.JSON(http.StatusForbidden, gin.H{"error": "Singpass email does not match authenticated user"})
			return
		}
		log.WithContext(ctx).Errorw("singpass callback rejected: internal error",
			"reason", "internal_error",
			"http_status", http.StatusInternalServerError,
			"state_prefix", trimPrefix(state, 8),
			"ctx_err", ctx.Err(),
			"error", err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	redirectURI := ""
	if config.Config != nil && config.Config.SystemConfig != nil {
		redirectURI = strings.TrimSpace(config.Config.SystemConfig.PostKYCRedirectURI)
	}
	if redirectURI == "" {
		log.WithContext(ctx).Infow("singpass callback succeeded",
			"reason", "ok_no_redirect",
			"http_status", http.StatusOK,
			"state_prefix", trimPrefix(state, 8),
		)
		c.JSON(http.StatusOK, gin.H{"message": "Callback accepted"})
		return
	}
	log.WithContext(ctx).Infow("singpass callback succeeded",
		"reason", "ok_redirect",
		"http_status", http.StatusFound,
		"state_prefix", trimPrefix(state, 8),
		"redirect_uri", redirectURI,
	)
	c.Redirect(http.StatusFound, redirectURI)
}

func trimPrefix(s string, n int) string {
	if n <= 0 || s == "" {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n]
}
