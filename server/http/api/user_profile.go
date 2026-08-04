package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	commonauth "github.com/nusiss-capstone-project/identity-mservice/common/auth"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/service"
)

// UserProfileData documents StandardResponse.data for the authenticated user profile.
type UserProfileData struct {
	Username     string `json:"username" example:"alice"`
	Email        string `json:"email" example:"a***e@example.com"`
	Language     string `json:"language" example:"en"`
	Market       string `json:"market" example:"SG"`
	KYCChecked   bool   `json:"kycChecked" example:"true"`
	RegisteredAt string `json:"registeredAt" example:"2026-05-16T10:00:00Z"`
}

// UserProfileHTTPResponse documents HTTP 200 for user profile.
type UserProfileHTTPResponse struct {
	Code    int             `json:"code" example:"0"`
	Message string          `json:"message" example:"success"`
	Data    UserProfileData `json:"data"`
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
	user, ok := commonauth.GetUser(c.Request.Context())
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

// UserUpdateProfile updates username, language, and/or market for the authenticated user.
// Market can only be set once when currently empty.
//
// @Summary Update user profile (user)
// @Tags user-profile
// @Accept json
// @Produce json
// @Param body body data.UpdateUserProfileRequest true "profile fields to update"
// @Success 200 {object} data.BaseResponse "success"
// @Failure 400 {object} data.BaseResponse "invalid input or market already set"
// @Failure 401 {object} data.BaseResponse "authentication required"
// @Failure 404 {object} data.BaseResponse "user not found"
// @Failure 500 {object} data.BaseResponse "internal error"
// @Router /identity-ms/v1/web/user-profile [put]
func UserUpdateProfile(c *gin.Context) {
	user, ok := commonauth.GetUser(c.Request.Context())
	if !ok {
		authError(c)
		return
	}
	var req data.UpdateUserProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		data.JSON(c, http.StatusBadRequest, -1, "invalid request body", nil)
		return
	}
	err := service.GetUserProfileService().UpdateProfile(c.Request.Context(), user.InternalUserID, &req)
	if err != nil {
		handleProfileUpdateErr(c, err)
		return
	}
	data.OK(c, nil)
}

func handleProfileUpdateErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrUserNotFound):
		data.JSON(c, http.StatusNotFound, -1, err.Error(), nil)
	case errors.Is(err, service.ErrMarketAlreadySet),
		errors.Is(err, service.ErrInvalidMarket),
		errors.Is(err, service.ErrInvalidLanguage),
		errors.Is(err, service.ErrInvalidArgument):
		data.JSON(c, http.StatusBadRequest, -1, err.Error(), nil)
	default:
		handleRepoErr(c, err)
	}
}
