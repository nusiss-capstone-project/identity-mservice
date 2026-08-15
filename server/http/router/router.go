package router

import (
	"context"
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
	r.Use(log.HTTPResponseIDMiddleware())
	r.Use(corsMiddleware())

	basicGroup := r.Group(serviceURIPrefix)
	{
		// High-frequency / non-business routes: no HTTP access log.
		basicGroup.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "pong",
			})
		})
		basicGroup.GET("/swagger/*any", gs.WrapHandler(
			swaggerFiles.Handler,
			gs.URL("/identity-ms/v1/swagger/doc.json"),
		))
	}

	// Business routes: enable request access logging.
	apiGroup := basicGroup.Group("")
	apiGroup.Use(commonauth.AuditMiddleware(func(ctx context.Context) commonauth.AuditLogger {
		return log.WithContext(ctx)
	}))
	apiGroup.Use(log.HTTPObservabilityMiddleware())
	{
		apiGroup.POST("/clerk/callback", api.ClerkCallback)
		apiGroup.GET("/kyc/singpass/callback", api.SingpassCallback)

		web := apiGroup.Group("/web")
		web.Use(commonauth.RequireUser())
		{
			web.GET("/user-profile", api.UserGetProfile)
			web.PUT("/user-profile", api.UserUpdateProfile)
			web.GET("/kyc/singpass/login", api.SingpassLogin)
		}

		admin := apiGroup.Group("/admin")
		admin.Use(commonauth.RequireRole(nil)) // authenticate only; any role may query current-user
		{
			admin.GET("/current-user", api.AdminGetCurrentUser)
		}
	}

	// Outside /identity-ms/v1 so Traefik ForwardAuth on that prefix cannot recurse.
	// Traefik ForwardAuth reuses the original request method, so accept any method.
	r.Any("/auth/forward", log.HTTPObservabilityMiddleware(), commonauth.RequireInternalNetwork(), api.AuthForward)

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
			commonauth.HeaderInternalUserID, commonauth.HeaderUserRole,
			log.RequestIDHeader, log.TraceIDHeader,
		},
		ExposeHeaders: []string{
			"Content-Length", commonauth.HeaderInternalUserID, commonauth.HeaderUserRole,
			log.RequestIDHeader, log.TraceIDHeader,
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
