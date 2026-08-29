package auth

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

// AuditLogger writes structured audit log lines.
// Compatible with zap.SugaredLogger (Infow).
type AuditLogger interface {
	Infow(msg string, keysAndValues ...any)
}

// AuditMiddleware logs method, host, referer, ip, url, user_id, role, status, and duration
// after the request completes. Message contains "[audit]" for easy filtering.
// Trace ids are attached both as fields and via loggerFromContext (when that
// logger enriches from the OpenTelemetry span).
//
// Place after otel middleware; user_id/role are read after c.Next() so nested
// RequireUser / RequireRole middlewares can populate context first.
func AuditMiddleware(loggerFromContext func(ctx context.Context) AuditLogger) gin.HandlerFunc {
	if loggerFromContext == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		ctx := c.Request.Context()
		logger := loggerFromContext(ctx)
		if logger == nil {
			return
		}

		method := ""
		host := ""
		url := ""
		ip := ""
		referer := ""
		if c.Request != nil {
			method = c.Request.Method
			host = c.Request.Host
			ip = c.ClientIP()
			referer = c.Request.Referer()
			if c.Request.URL != nil {
				url = c.Request.URL.RequestURI()
			}
		}

		var userID int64
		role := ""
		if user, ok := GetUser(ctx); ok {
			userID = user.InternalUserID
			role = user.Role
		} else if u, ok := userFromHeaders(c); ok {
			userID = u.InternalUserID
			role = u.Role
		}

		traceID, spanID := auditTraceIDs(ctx)
		durationMs := float64(time.Since(start).Microseconds()) / 1000

		logger.Infow("[audit] http request",
			"method", method,
			"host", host,
			"referer", referer,
			"ip", ip,
			"url", url,
			"user_id", userID,
			"role", role,
			"status", c.Writer.Status(),
			"duration_ms", durationMs,
			"trace_id", traceID,
			"span_id", spanID,
		)
	}
}

func auditTraceIDs(ctx context.Context) (string, string) {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}
