package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/proxy"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
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
	singpassProxy proxy.SingpassProxy
	userDao       dao.UserDao
	stateStore    KYCStateStore //todo replace redis
}

func newKYCService(
	singpassProxy proxy.SingpassProxy,
	userDao dao.UserDao,
	stateStore KYCStateStore,
) KYCService {
	return &kycServiceImpl{
		singpassProxy: singpassProxy,
		userDao:       userDao,
		stateStore:    stateStore,
	}
}

func (k *kycServiceImpl) StartSingpassLogin(_ context.Context, userID int64, email string) (string, error) {
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
	return proxy.BuildAuthorizeURL(state, nonce), nil
}

// SingpassCallback exchanges the auth code and updates KYC for the user bound to state.
func (k *kycServiceImpl) SingpassCallback(ctx context.Context, code, state string) error {
	pending, ok := k.stateStore.Consume(state)
	if !ok {
		return ErrInvalidOAuthState
	}

	accessToken, err := k.singpassProxy.GetAccessToken(ctx, code)
	if err != nil {
		return err
	}
	userInfo, err := k.singpassProxy.GetUserInfo(ctx, accessToken)
	if err != nil {
		return err
	}
	log.Logger.Infof("user info: %s", userInfo)

	if pending.Email != "" && !emailsMatchForKYC(pending.Email, userInfo.Email) {
		log.Logger.Warnf("singpass email mismatch for user %d", pending.InternalUserID)
		return ErrKYCEmailMismatch
	}

	kycStatus := model.KYCStatusFailed
	if userInfo.Name != "" {
		kycStatus = model.KYCStatusPassed
	}
	return k.userDao.UpdateKYCStatus(ctx, pending.InternalUserID, kycStatus)
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
		)
	})
	return kycServiceInstance
}
