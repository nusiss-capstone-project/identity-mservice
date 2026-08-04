package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/kafka/producer"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"github.com/nusiss-capstone-project/identity-mservice/server/util"
	"gorm.io/gorm"
)

type UserMappingService interface {
	CreateUser(ctx context.Context, clerkCallbackData *data.ClerkCallbackData) error
}

var (
	userMappingServiceOnce sync.Once
	userMappingServiceInst UserMappingService
)

type userServiceImpl struct {
	userAuthMappingDao dao.UserAuthMappingDao
	userDao            dao.UserDao
	tx                 repository.TxBeginner
	registeredProducer producer.UserRegisteredProducer
}

func newUserMappingService(
	userAuthMappingDao dao.UserAuthMappingDao,
	userDao dao.UserDao,
	tx repository.TxBeginner,
	registeredProducer producer.UserRegisteredProducer,
) UserMappingService {
	return &userServiceImpl{
		userAuthMappingDao: userAuthMappingDao,
		userDao:            userDao,
		tx:                 tx,
		registeredProducer: registeredProducer,
	}
}

func GetUserMappingService() UserMappingService {
	userMappingServiceOnce.Do(func() {
		userMappingServiceInst = newUserMappingService(
			dao.GetUserAuthMappingDao(),
			dao.GetUserDao(),
			repository.DB,
			producer.GetUserRegisteredProducer(),
		)
	})
	return userMappingServiceInst
}

func (s *userServiceImpl) CreateUser(ctx context.Context, clerkCallbackData *data.ClerkCallbackData) error {
	clerkUserID := clerkCallbackData.ClerkUserID()
	email := clerkCallbackData.EmailAddress()
	if email == "" {
		log.Logger.Warnf("Email is not found for clerk user: %s, skipping user creation", clerkUserID)
		return nil // skip if email is not found
	}

	existing, err := s.userAuthMappingDao.GetByClerkUserID(ctx, clerkUserID)
	if err != nil {
		log.WithContext(ctx).Errorf("Failed to get user mapping by clerk user ID: %s, error: %v", clerkUserID, err)
		return err
	}
	if existing != nil {
		log.WithContext(ctx).Infof("User mapping already exists for clerk user: %s", clerkUserID)
		return nil
	}

	userMapping, err := s.userAuthMappingDao.GetByEmail(ctx, email)
	if err != nil {
		log.WithContext(ctx).Errorf("Failed to get user mapping by email: %s, error: %v", email, err)
		return err
	}
	if userMapping != nil {
		log.Logger.Infof("User mapping already exists for email: %s", util.MaskEmail(email))
		return nil
	}

	user := &model.User{
		Name:      randomGenName(),
		KYCStatus: model.KYCStatusPending,
		CreatedAt: time.Now(),
	}
	if err = s.tx.Transaction(func(tx *gorm.DB) error {
		if err = s.userDao.CreateInTransaction(tx, user); err != nil {
			return err
		}
		userMapping = &model.UserAuthMapping{
			ClerkUserID:    clerkUserID,
			Email:          email,
			InternalUserID: user.ID,
			Role:           model.RoleUser,
		}
		return s.userAuthMappingDao.CreateInTransaction(tx, userMapping)
	}); err != nil {
		return err
	}
	InvalidateUserProfileCache(ctx, user.ID)

	if err = s.registeredProducer.PublishUserRegistered(ctx, user.ID, user.CreatedAt); err != nil {
		log.WithContext(ctx).Errorf("publish user registered event user=%d: %v", user.ID, err)
		return err
	}
	return nil
}

func randomGenName() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return fmt.Sprintf("User%d", time.Now().UnixNano()%1_000_000)
	}
	return fmt.Sprintf("User%06d", n.Int64())
}
