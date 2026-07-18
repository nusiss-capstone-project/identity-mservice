package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/service"
	svix "github.com/svix/svix-webhooks/go"
)

const maxClerkWebhookBody = 1 << 20 // 1 MiB

// ClerkCallbackErrorResponse documents HTTP error responses for the Clerk webhook.
type ClerkCallbackErrorResponse struct {
	Error string `json:"error" example:"Missing svix headers"`
}

// ClerkCallback handles Clerk user lifecycle webhook events delivered via Svix.
// @Summary Clerk webhook callback
// @Description Verifies Svix signature headers and accepts Clerk webhook events (e.g. user.created).
// @Tags clerk-webhook
// @Accept json
// @Produce json
// @Param svix-id header string true "Svix message ID"
// @Param svix-signature header string true "Svix HMAC signature"
// @Param svix-timestamp header string true "Unix timestamp of the webhook message"
// @Param body body object true "Raw Clerk webhook event JSON payload"
// @Success 200 "webhook accepted"
// @Failure 400 {object} ClerkCallbackErrorResponse "missing svix headers, invalid body, or invalid signature"
// @Failure 500 {object} ClerkCallbackErrorResponse "webhook verification init failed"
// @Router /identity-ms/v1/clerk/callback [post]
func ClerkCallback(c *gin.Context) {
	log.WithContext(c.Request.Context()).Infow("clerk callback received")

	secret := os.Getenv("CLERK_WEBHOOK_SECRET")

	// 2. obtain Svix signature headers
	headers := c.Request.Header
	svixId := headers.Get("svix-id")
	svixSignature := headers.Get("svix-signature")
	svixTimestamp := headers.Get("svix-timestamp")

	if svixId == "" || svixSignature == "" || svixTimestamp == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing svix headers"})
		return
	}

	// 3. read request body (capped to avoid memory exhaustion before signature verification)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxClerkWebhookBody)
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Request body too large"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Read body failed"})
		return
	}
	defer func() {
		if err := c.Request.Body.Close(); err != nil {
			log.WithContext(c.Request.Context()).Errorf("Failed to close request body: %v", err)
		}
	}()

	// 4. initialize validator and verify signature
	wh, err := svix.NewWebhook(secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Webhook init failed"})
		return
	}

	err = wh.Verify(payload, headers)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
		return
	}

	// 5. signature verified, process user.created event
	var request data.ClerkCallbackRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if request.Type != "user.created" {
		c.Status(http.StatusOK)
		return
	}
	if request.Data == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Data is required"})
		return
	}
	if request.Data.ClerkUserID() == "" || request.Data.EmailAddress() == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user data"})
		return
	}

	// 6. create user mapping
	err = service.GetUserMappingService().CreateUser(c.Request.Context(), request.Data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user mapping"})
		return
	}
	// 返回 200 状态码告知 Clerk 接收成功
	c.Status(http.StatusOK)
}
