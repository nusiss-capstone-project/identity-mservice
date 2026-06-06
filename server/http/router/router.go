package router

import (
	"github.com/gin-gonic/gin"

	_ "github.com/nusiss-capstone-project/identity-mservice/server/docs"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/api"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	swaggerFiles "github.com/swaggo/files"
	gs "github.com/swaggo/gin-swagger"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

const (
	serviceURIPrefix = "/identity-ms/v1"
)

func NewRouter() *gin.Engine {
	r := gin.New()
	r.Use(log.RecoveryMiddleware())
	r.Use(otelgin.Middleware(data.ServiceName))
	r.Use(log.HTTPObservabilityMiddleware())

	basicGroup := r.Group(serviceURIPrefix)
	{
		basicGroup.GET("/swagger/*any", gs.WrapHandler(
			swaggerFiles.Handler,
			gs.URL("/identity-ms/v1/swagger/doc.json"),
		))
		basicGroup.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "pong",
			})
		})
	}

	v1 := r.Group(serviceURIPrefix + "/:client")
	{
		v1.Use(validateClient())
		v1.POST("/items", api.CreateItem)
		v1.GET("/items/:item_id", api.GetItems)
	}
	return r
}

func validateClient() gin.HandlerFunc {
	return func(c *gin.Context) {
		client := c.Param("client")
		if client != "merchant" && client != "customer" {
			c.JSON(400, gin.H{"error": "Invalid client type"})
			c.Abort()
			return
		}
		c.Next()
	}
}
