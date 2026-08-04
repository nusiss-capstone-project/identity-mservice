package router

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	commonauth "github.com/nusiss-capstone-project/identity-mservice/common/auth"
	"github.com/nusiss-capstone-project/identity-mservice/server/config"
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
	r.Use(corsMiddleware())

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
	basicGroup.POST("/clerk/callback", api.ClerkCallback)
	basicGroup.GET("/kyc/singpass/callback", api.SingpassCallback)

	// Outside /identity-ms/v1 so Traefik ForwardAuth on that prefix cannot recurse.
	// Traefik ForwardAuth reuses the original request method, so accept any method.
	r.Any("/auth/forward", commonauth.RequireInternalNetwork(), api.AuthForward)

	web := basicGroup.Group("/web")
	web.Use(commonauth.RequireUser())
	{
		web.GET("/user-profile", api.UserGetProfile)
		web.PUT("/user-profile", api.UserUpdateProfile)
		web.GET("/kyc/singpass/login", api.SingpassLogin)
	}

	admin := basicGroup.Group("/admin")
	admin.Use(commonauth.RequireRole(nil)) // authenticate only; any role may query current-user
	{
		admin.GET("/current-user", api.AdminGetCurrentUser)
	}

	return r
}

func corsMiddleware() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins: allowedOrigins(),
		AllowMethods: []string{
			"GET", "POST", "PUT", "DELETE", "OPTIONS",
		},
		AllowHeaders: []string{
			"Origin", "Content-Type", "Accept", "Authorization",
			commonauth.HeaderInternalUserID, commonauth.HeaderUserRole, log.RequestIDHeader,
		},
		ExposeHeaders: []string{
			"Content-Length", commonauth.HeaderInternalUserID, commonauth.HeaderUserRole, log.RequestIDHeader,
		},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}

func allowedOrigins() []string {
	if config.Config == nil || config.Config.SystemConfig == nil {
		return []string{}
	}
	return config.Config.SystemConfig.AllowedOrigins
}
