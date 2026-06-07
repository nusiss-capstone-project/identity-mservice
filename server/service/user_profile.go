package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"github.com/nusiss-capstone-project/identity-mservice/server/util"
)

type UserProfileService interface {
	GetProfile(ctx context.Context, userID int64, email string) (*data.UserProfileVO, error)
}

type UserProfileServiceImpl struct {
	users dao.UserDao
}

var (
	userProfileServiceOnce sync.Once
	userProfileServiceInst *UserProfileServiceImpl
)

func NewUserProfileService(users dao.UserDao) *UserProfileServiceImpl {
	return &UserProfileServiceImpl{users: users}
}

func GetUserProfileService() *UserProfileServiceImpl {
	userProfileServiceOnce.Do(func() {
		userProfileServiceInst = NewUserProfileService(dao.GetUserDao())
	})
	return userProfileServiceInst
}

func (s *UserProfileServiceImpl) GetProfile(ctx context.Context, userID int64, email string) (*data.UserProfileVO, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		log.Logger.Errorf("Failed to get user profile: %v", err)
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}
	if user == nil {
		return nil, nil
	}
	return &data.UserProfileVO{
		Username:     user.Name,
		Email:        util.MaskEmail(email),
		KYCChecked:   user.KYCStatus == model.KYCStatusPassed,
		RegisteredAt: user.CreatedAt.Format(time.RFC3339),
	}, nil
}
