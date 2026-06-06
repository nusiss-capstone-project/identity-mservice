package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
)

func authError(c *gin.Context) {
	data.JSON(c, http.StatusUnauthorized, -1, "Authentication required", nil)
}

func handleRepoErr(c *gin.Context, err error) {
	if err == nil {
		return
	}
	if err == dao.ErrDatabaseDisabled {
		data.JSON(c, http.StatusServiceUnavailable, -1, err.Error(), nil)
		return
	}
	data.JSON(c, http.StatusInternalServerError, -1, err.Error(), nil)
}
