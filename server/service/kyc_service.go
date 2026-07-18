package service

import (
	"context"
	"sync"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/proxy"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
)

type KYCService interface {
	SingpassCallback(ctx context.Context, code string) error
}

type kycServiceImpl struct {
	singpassProxy  proxy.SingpassProxy
	userDao        dao.UserDao
	userMappingDao dao.UserAuthMappingDao
}

// Verify implements [KYCService].
func (k *kycServiceImpl) SingpassCallback(ctx context.Context, code string) error {
	accessToken, err := k.singpassProxy.GetAccessToken(ctx, code)
	if err != nil {
		return err
	}
	userInfo, err := k.singpassProxy.GetUserInfo(ctx, accessToken)
	if err != nil {
		return err
	}
	log.Logger.Infof("user info: %+v", userInfo)
	userMapping, err := k.userMappingDao.GetByEmail(ctx, userInfo.Email)
	if err != nil {
		return err
	}
	if userMapping == nil {
		log.Logger.Warnf("user mapping not found for email: %s", userInfo.Email)
		return nil
	}
	kycStatus := model.KYCStatusFailed
	if userInfo.Name != "" {
		kycStatus = model.KYCStatusPassed
	}
	err = k.userDao.UpdateKYCStatus(ctx, userMapping.InternalUserID, kycStatus)
	if err != nil {
		return err
	}
	return nil
}

var (
	kycServiceSyncOnce sync.Once
	kycServiceInstance KYCService
)

func GetKYCService() KYCService {
	return &kycServiceImpl{
		singpassProxy:  proxy.GetSingpassProxy(),
		userDao:        dao.GetUserDao(),
		userMappingDao: dao.GetUserAuthMappingDao(),
	}
}
