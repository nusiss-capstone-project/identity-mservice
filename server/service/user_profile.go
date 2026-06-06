package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
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
		Email:        maskEmail(email),
		KYCChecked:   user.KYCStatus == model.KYCStatusPassed,
		RegisteredAt: user.CreatedAt.Format(time.RFC3339),
	}, nil
}

func maskEmail(email string) string {
	email = strings.TrimSpace(email)
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" {
		return maskString(email)
	}
	return maskString(local) + "@" + domain
}

func maskString(value string) string {
	switch len(value) {
	case 0:
		return ""
	case 1:
		return "*"
	case 2:
		return value[:1] + "*"
	default:
		return value[:1] + "***" + value[len(value)-1:]
	}
}
