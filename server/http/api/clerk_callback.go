package api

import (
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	svix "github.com/svix/svix-webhooks/go"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
)

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
	secret := os.Getenv("CLERK_WEBHOOK_SECRET")

	// 2. 获取 Svix 签名请求头
	headers := c.Request.Header
	svixId := headers.Get("svix-id")
	svixSignature := headers.Get("svix-signature")
	svixTimestamp := headers.Get("svix-timestamp")

	if svixId == "" || svixSignature == "" || svixTimestamp == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing svix headers"})
		return
	}

	// 3. 读取请求体
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Read body failed"})
		return
	}
	defer c.Request.Body.Close()

	// 4. 初始化验证器并验证签名
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

	// 5. 签名验证通过，处理 user.created 事件
	// 提示：可以使用 json.Unmarshal 将 payload 解析为你需要的结构体
	log.Logger.Infof("收到合法的 Clerk Webhook: %s", string(payload))

	// 返回 200 状态码告知 Clerk 接收成功
	c.Status(http.StatusOK)
}
