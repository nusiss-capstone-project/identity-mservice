package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type captureLogger struct {
	msg    string
	fields map[string]any
}

func (l *captureLogger) Infow(msg string, keysAndValues ...any) {
	l.msg = msg
	l.fields = map[string]any{}
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok {
			continue
		}
		l.fields[key] = keysAndValues[i+1]
	}
}

func TestAuditMiddleware_logsAfterHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	captured := &captureLogger{}

	r := gin.New()
	r.Use(AuditMiddleware(func(ctx context.Context) AuditLogger {
		return captured
	}))
	r.Use(RequireUser())
	r.GET("/web/profile", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/web/profile?x=1", nil)
	req.Host = "identity.example.com"
	req.Header.Set(HeaderInternalUserID, "42")
	req.Header.Set(HeaderUserRole, RoleUser)
	req.Header.Set("Referer", "https://app.example.com/kyc")
	req.RemoteAddr = "203.0.113.10:54321"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "[audit] http request", captured.msg)
	require.Equal(t, http.MethodGet, captured.fields["method"])
	require.Equal(t, "identity.example.com", captured.fields["host"])
	require.Equal(t, "https://app.example.com/kyc", captured.fields["referer"])
	require.Equal(t, "203.0.113.10", captured.fields["ip"])
	require.Equal(t, "/web/profile?x=1", captured.fields["url"])
	require.Equal(t, int64(42), captured.fields["user_id"])
	require.Equal(t, RoleUser, captured.fields["role"])
	require.Equal(t, http.StatusOK, captured.fields["status"])
	_, ok := captured.fields["duration_ms"].(float64)
	require.True(t, ok)
	require.Contains(t, captured.fields, "trace_id")
	require.Contains(t, captured.fields, "span_id")
}

func TestAuditMiddleware_nilLoggerFromContextIsNoop(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuditMiddleware(nil))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
}

func TestAuditTraceIDs_emptyWithoutSpan(t *testing.T) {
	traceID, spanID := auditTraceIDs(context.Background())
	require.Empty(t, traceID)
	require.Empty(t, spanID)
}
