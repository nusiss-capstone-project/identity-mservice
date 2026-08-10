package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/kafka/producer"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/proxy"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"github.com/nusiss-capstone-project/identity-mservice/server/util"
)

var (
	ErrInvalidOAuthState = errors.New("invalid or expired oauth state")
	ErrKYCEmailMismatch  = errors.New("singpass email does not match authenticated user")
)

type KYCService interface {
	StartSingpassLogin(ctx context.Context, userID int64, email string) (authorizeURL string, err error)
	SingpassCallback(ctx context.Context, code, state string) error
}

type kycServiceImpl struct {
	singpassProxy   proxy.SingpassProxy
	userDao         dao.UserDao
	stateStore      KYCStateStore //todo replace redis
	kycCompleteProd producer.UserKYCCompleteProducer
}

func newKYCService(
	singpassProxy proxy.SingpassProxy,
	userDao dao.UserDao,
	stateStore KYCStateStore,
	kycCompleteProd producer.UserKYCCompleteProducer,
) KYCService {
	return &kycServiceImpl{
		singpassProxy:   singpassProxy,
		userDao:         userDao,
		stateStore:      stateStore,
		kycCompleteProd: kycCompleteProd,
	}
}

func (k *kycServiceImpl) StartSingpassLogin(ctx context.Context, userID int64, email string) (string, error) {
	state, err := proxy.RandomOAuthParam()
	if err != nil {
		return "", fmt.Errorf("generate oauth state: %w", err)
	}
	nonce, err := proxy.RandomOAuthParam()
	if err != nil {
		return "", fmt.Errorf("generate oauth nonce: %w", err)
	}
	k.stateStore.Save(state, KYCPending{
		InternalUserID: userID,
		Email:          email,
	})
	authorizeURL := proxy.BuildAuthorizeURL(state, nonce)
	log.WithContext(ctx).Infow("singpass login started",
		"user_id", userID,
		"state_len", len(state),
		"state_prefix", trimStatePrefix(state),
		"has_email", strings.TrimSpace(email) != "",
	)
	return authorizeURL, nil
}

// SingpassCallback exchanges the auth code and updates KYC for the user bound to state.
func (k *kycServiceImpl) SingpassCallback(ctx context.Context, code, state string) error {
	start := time.Now()
	log.WithContext(ctx).Infow("singpass callback service begin",
		"code_len", len(code),
		"state_len", len(state),
		"state_prefix", trimStatePrefix(state),
		"ctx_err", ctx.Err(),
	)

	pending, ok := k.stateStore.Consume(state)
	if !ok {
		log.WithContext(ctx).Warnw("singpass callback state consume failed",
			"stage", "consume_state",
			"state_len", len(state),
			"state_prefix", trimStatePrefix(state),
			"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
		)
		return ErrInvalidOAuthState
	}
	log.WithContext(ctx).Infow("singpass callback state consumed",
		"stage", "consume_state",
		"user_id", pending.InternalUserID,
		"has_pending_email", strings.TrimSpace(pending.Email) != "",
		"state_prefix", trimStatePrefix(state),
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
	)

	// State/code are one-time. Client/gateway may cancel the HTTP request mid-flight;
	// keep processing with a detached timeout so KYC can still complete.
	workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	accessToken, err := k.singpassProxy.GetAccessToken(workCtx, code)
	if err != nil {
		log.WithContext(ctx).Errorw("singpass get access token failed",
			"stage", "get_access_token",
			"user_id", pending.InternalUserID,
			"req_ctx_err", ctx.Err(),
			"work_ctx_err", workCtx.Err(),
			"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
			"error", err,
		)
		return err
	}
	log.WithContext(ctx).Infow("singpass access token obtained",
		"stage", "get_access_token",
		"user_id", pending.InternalUserID,
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
	)

	userInfo, err := k.singpassProxy.GetUserInfo(workCtx, accessToken)
	if err != nil {
		log.WithContext(ctx).Errorw("singpass get userinfo failed",
			"stage", "get_userinfo",
			"user_id", pending.InternalUserID,
			"req_ctx_err", ctx.Err(),
			"work_ctx_err", workCtx.Err(),
			"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
			"error", err,
		)
		return err
	}
	singpassEmail := ""
	if userInfo != nil {
		singpassEmail = userInfo.Email
	}
	log.WithContext(ctx).Infow("singpass user info received",
		"stage", "get_userinfo",
		"user_id", pending.InternalUserID,
		"has_name", userInfo != nil && userInfo.Name != "",
		"has_email", strings.TrimSpace(singpassEmail) != "",
		"pending_email_masked", util.MaskEmail(pending.Email),
		"singpass_email_masked", util.MaskEmail(singpassEmail),
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
	)

	if pending.Email != "" && !emailsMatchForKYC(pending.Email, singpassEmail) {
		log.WithContext(ctx).Warnw("singpass email mismatch",
			"stage", "email_check",
			"user_id", pending.InternalUserID,
			"pending_email_masked", util.MaskEmail(pending.Email),
			"singpass_email_masked", util.MaskEmail(singpassEmail),
			"singpass_email_empty", strings.TrimSpace(singpassEmail) == "",
			"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
		)
		return ErrKYCEmailMismatch
	}

	kycStatus := model.KYCStatusFailed
	if userInfo != nil && userInfo.Name != "" {
		kycStatus = model.KYCStatusPassed
	}
	kycUpdatedAt := time.Now().UTC()
	log.WithContext(ctx).Infow("singpass updating kyc status",
		"stage", "update_kyc",
		"user_id", pending.InternalUserID,
		"kyc_status", kycStatus,
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
	)

	if err = k.userDao.UpdateKYCStatus(workCtx, pending.InternalUserID, kycStatus); err != nil {
		log.WithContext(ctx).Errorw("singpass update kyc status failed",
			"stage", "update_kyc",
			"user_id", pending.InternalUserID,
			"kyc_status", kycStatus,
			"req_ctx_err", ctx.Err(),
			"work_ctx_err", workCtx.Err(),
			"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
			"error", err,
		)
		return err
	}
	InvalidateUserProfileCache(workCtx, pending.InternalUserID)

	log.WithContext(ctx).Infow("singpass publishing kyc complete event",
		"stage", "publish_kafka",
		"user_id", pending.InternalUserID,
		"kyc_status", kycStatus,
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
	)
	if err = k.kycCompleteProd.PublishUserKYCComplete(workCtx, pending.InternalUserID, kycStatus, kycUpdatedAt); err != nil {
		log.WithContext(ctx).Errorw("publish user kyc complete event failed",
			"stage", "publish_kafka",
			"user_id", pending.InternalUserID,
			"kyc_status", kycStatus,
			"req_ctx_err", ctx.Err(),
			"work_ctx_err", workCtx.Err(),
			"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
			"error", err,
		)
		return err
	}
	log.WithContext(ctx).Infow("singpass callback service completed",
		"stage", "done",
		"user_id", pending.InternalUserID,
		"kyc_status", kycStatus,
		"req_ctx_err", ctx.Err(),
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000,
	)
	return nil
}

// emailsMatchForKYC compares the authenticated user's email with Singpass email.
// Matches if equal (case-insensitive), or if pending email with "+clerk_test" removed equals Singpass email.
func emailsMatchForKYC(pendingEmail, singpassEmail string) bool {
	pending := strings.TrimSpace(pendingEmail)
	singpass := strings.TrimSpace(singpassEmail)
	if strings.EqualFold(pending, singpass) {
		return true
	}
	normalizedPending := strings.ReplaceAll(pending, "+clerk_test", "")
	return strings.EqualFold(normalizedPending, singpass)
}

func trimStatePrefix(state string) string {
	const n = 8
	if state == "" {
		return ""
	}
	if len(state) <= n {
		return state
	}
	return state[:n]
}

var (
	kycServiceSyncOnce sync.Once
	kycServiceInstance KYCService
)

func GetKYCService() KYCService {
	kycServiceSyncOnce.Do(func() {
		kycServiceInstance = newKYCService(
			proxy.GetSingpassProxy(),
			dao.GetUserDao(),
			GetKYCStateStore(),
			producer.GetUserKYCCompleteProducer(),
		)
	})
	return kycServiceInstance
}
