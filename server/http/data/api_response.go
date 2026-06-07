package data

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const CodeSuccess = 0

// JSON writes the common {code,message,data} response.
func JSON(c *gin.Context, httpStatus int, code int, message string, payload any) {
	c.JSON(httpStatus, gin.H{
		"code":    code,
		"message": message,
		"data":    payload,
	})
}

// OK sends HTTP 200 with code 0.
func OK(c *gin.Context, payload any) {
	JSON(c, http.StatusOK, CodeSuccess, "success", payload)
}
