package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nusiss-capstone-project/identity-mservice/server/auth"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/service"
)

// UserProfileData documents StandardResponse.data for the authenticated user profile.
type UserProfileData struct {
	Username     string `json:"username" example:"alice"`
	Email        string `json:"email" example:"a***e@example.com"`
	KYCChecked   bool   `json:"kycChecked" example:"true"`
	RegisteredAt string `json:"registeredAt" example:"2026-05-16T10:00:00Z"`
}

// UserProfileHTTPResponse documents HTTP 200 for user profile.
type UserProfileHTTPResponse struct {
	Code    int             `json:"code" example:"0"`
	Message string          `json:"message" example:"success"`
	Data    UserProfileData   `json:"data"`
}

// UserGetProfile returns the authenticated user's profile.
// @Summary Get user profile (user)
// @Tags user-profile
// @Produce json
// @Success 200 {object} UserProfileHTTPResponse "success"
// @Failure 404 {object} data.BaseResponse "user not found"
// @Failure 500 {object} data.BaseResponse "internal error"
// @Router /identity-ms/v1/web/user-profile [get]
func UserGetProfile(c *gin.Context) {
	user, ok := auth.GetUser(c.Request.Context())
	if !ok {
		authError(c)
		return
	}
	profile, err := service.GetUserProfileService().GetProfile(c.Request.Context(), user.InternalUserID, user.Email)
	if err != nil {
		handleRepoErr(c, err)
		return
	}
	if profile == nil {
		data.JSON(c, http.StatusNotFound, -1, "user not found", nil)
		return
	}
	data.OK(c, profile)
}
