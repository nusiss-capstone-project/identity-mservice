package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nusiss-capstone-project/identity-mservice/server/proxy"
	"github.com/nusiss-capstone-project/identity-mservice/server/service"
)

// SingpassLogin redirects to Singpass authorize using scope from config.yml.
// @Summary Start Singpass login
// @Description Redirects to MockPass/Singpass authorize with configured scope.
// @Tags singpass
// @Success 302 "redirect to singpass authorize"
// @Router /identity-ms/v1/kyc/singpass/login [get]
func SingpassLogin(c *gin.Context) {
	state, err := proxy.RandomOAuthParam()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}
	nonce, err := proxy.RandomOAuthParam()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate nonce"})
		return
	}
	c.Redirect(http.StatusFound, proxy.BuildAuthorizeURL(state, nonce))
}

// SingpassCallback handles Singpass callback.
// @Summary Singpass callback
// @Description Handles Singpass callback.
// @Tags singpass
// @Accept json
// @Produce json
// @Param code query string true "Singpass code"
// @Success 200 "callback accepted"
// @Failure 400 {object} data.BaseResponse "invalid code"
// @Router /identity-ms/v1/kyc/singpass/callback [get]
func SingpassCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}
	err := service.GetKYCService().SingpassCallback(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Callback accepted"})
}
