package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	commonauth "github.com/nusiss-capstone-project/identity-mservice/common/auth"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/service"
)

// CurrentUserData is the payload for the current-user endpoint.
type CurrentUserData struct {
	UserID   int64  `json:"userId" example:"1"`
	Username string `json:"username" example:"alice"`
	Role     string `json:"role" example:"admin"`
}

// CurrentUserHTTPResponse documents HTTP 200 for current user.
type CurrentUserHTTPResponse struct {
	Code    int             `json:"code" example:"0"`
	Message string          `json:"message" example:"success"`
	Data    CurrentUserData `json:"data"`
}

// AdminGetCurrentUser returns the authenticated caller's user id, username, and role.
// Authentication is required; no role authorization is enforced. Username is loaded from DB.
//
// @Summary Get current user
// @Tags admin
// @Produce json
// @Success 200 {object} CurrentUserHTTPResponse "success"
// @Failure 401 {object} data.BaseResponse "authentication required"
// @Failure 404 {object} data.BaseResponse "user not found"
// @Failure 500 {object} data.BaseResponse "internal error"
// @Router /identity-ms/v1/admin/current-user [get]
func AdminGetCurrentUser(c *gin.Context) {
	authUser, ok := commonauth.GetUser(c.Request.Context())
	if !ok {
		authError(c)
		return
	}
	user, err := service.GetUserProfileService().GetUser(c.Request.Context(), authUser.InternalUserID)
	if err != nil {
		handleRepoErr(c, err)
		return
	}
	if user == nil {
		data.JSON(c, http.StatusNotFound, -1, "user not found", nil)
		return
	}
	data.OK(c, CurrentUserData{
		UserID:   authUser.InternalUserID,
		Username: user.Name,
		Role:     authUser.Role,
	})
}
