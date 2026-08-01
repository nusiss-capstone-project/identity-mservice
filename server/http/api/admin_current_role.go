package api

import (
	"github.com/gin-gonic/gin"

	commonauth "github.com/nusiss-capstone-project/identity-mservice/common/auth"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
)

// CurrentRoleData is the payload for the current-role endpoint.
type CurrentRoleData struct {
	Role string `json:"role" example:"admin"`
}

// CurrentRoleHTTPResponse documents HTTP 200 for current role.
type CurrentRoleHTTPResponse struct {
	Code    int             `json:"code" example:"0"`
	Message string          `json:"message" example:"success"`
	Data    CurrentRoleData `json:"data"`
}

// AdminGetCurrentRole returns the authenticated caller's role from identity headers.
// Authentication is required; no role authorization is enforced.
//
// @Summary Get current role
// @Tags admin
// @Produce json
// @Success 200 {object} CurrentRoleHTTPResponse "success"
// @Failure 401 {object} data.BaseResponse "authentication required"
// @Router /identity-ms/v1/admin/current-role [get]
func AdminGetCurrentRole(c *gin.Context) {
	user, ok := commonauth.GetUser(c.Request.Context())
	if !ok {
		authError(c)
		return
	}
	data.OK(c, CurrentRoleData{Role: user.Role})
}
