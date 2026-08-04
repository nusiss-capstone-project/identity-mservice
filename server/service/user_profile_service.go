package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"github.com/nusiss-capstone-project/identity-mservice/server/util"
)

var (
	ErrMarketAlreadySet = errors.New("market already set")
	ErrInvalidMarket    = errors.New("invalid market")
	ErrInvalidLanguage  = errors.New("invalid language")
)

type UserProfileService interface {
	GetProfile(ctx context.Context, userID int64, email string) (*data.UserProfileVO, error)
	UpdateProfile(ctx context.Context, userID int64, req *data.UpdateUserProfileRequest) error
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
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	return &data.UserProfileVO{
		Username:     user.Name,
		Email:        util.MaskEmail(email),
		Language:     user.Language,
		Market:       user.Market,
		KYCChecked:   user.KYCStatus == model.KYCStatusPassed,
		RegisteredAt: user.CreatedAt.Format(time.RFC3339),
	}, nil
}

// GetUser loads the user row by internal id. Returns nil, nil when not found.
func (s *UserProfileServiceImpl) GetUser(ctx context.Context, userID int64) (*model.User, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		log.Logger.Errorf("Failed to get user: %v", err)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// UpdateProfile partially updates username/language/market.
// Market may only be initialized once; repeating the same value is a no-op,
// but a different value returns ErrMarketAlreadySet.
func (s *UserProfileServiceImpl) UpdateProfile(ctx context.Context, userID int64, req *data.UpdateUserProfileRequest) error {
	if req == nil {
		return ErrInvalidArgument
	}
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	update := &model.User{}
	hasUpdate := false
	if username := strings.TrimSpace(req.Username); username != "" {
		update.Name = username
		hasUpdate = true
	}
	if language := strings.TrimSpace(req.Language); language != "" {
		if !data.IsValidLanguage(language) {
			return ErrInvalidLanguage
		}
		update.Language = language
		hasUpdate = true
	}
	if market := strings.TrimSpace(req.Market); market != "" {
		if !data.IsValidMarket(market) {
			return ErrInvalidMarket
		}
		existing := strings.TrimSpace(user.Market)
		if existing != "" && existing != market {
			return ErrMarketAlreadySet
		}
		if existing == "" {
			update.Market = market
			hasUpdate = true
		}
	}
	if !hasUpdate {
		return nil
	}
	if err := s.users.UpdateProfile(ctx, userID, update); err != nil {
		return err
	}
	InvalidateUserProfileCache(ctx, userID)
	return nil
}
