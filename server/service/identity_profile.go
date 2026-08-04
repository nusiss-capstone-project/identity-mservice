package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	cacheredis "github.com/nusiss-capstone-project/identity-mservice/server/repository/redis"
)

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrInvalidArgument  = errors.New("invalid argument")
	userProfileCacheTTL = time.Hour
)

// UserProfileAggregate is users + user_auth_mapping joined for gRPC GetUserProfile.
type UserProfileAggregate struct {
	UserID       int64     `json:"userId"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Market       string    `json:"market"`
	KYCStatus    string    `json:"kycStatus"`
	RegisteredAt time.Time `json:"registeredAt"`
}

type IdentityProfileService interface {
	GetUserProfile(ctx context.Context, userID int64) (*UserProfileAggregate, error)
}

type identityProfileServiceImpl struct {
	users    dao.UserDao
	mappings dao.UserAuthMappingDao
}

var (
	identityProfileOnce sync.Once
	identityProfileInst IdentityProfileService
)

func newIdentityProfileService(users dao.UserDao, mappings dao.UserAuthMappingDao) IdentityProfileService {
	return &identityProfileServiceImpl{users: users, mappings: mappings}
}

func GetIdentityProfileService() IdentityProfileService {
	identityProfileOnce.Do(func() {
		identityProfileInst = newIdentityProfileService(dao.GetUserDao(), dao.GetUserAuthMappingDao())
	})
	return identityProfileInst
}

func (s *identityProfileServiceImpl) GetUserProfile(ctx context.Context, userID int64) (*UserProfileAggregate, error) {
	if userID <= 0 {
		return nil, ErrInvalidArgument
	}
	if cached, ok := getUserProfileCache(ctx, userID); ok {
		return cached, nil
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	mapping, err := s.mappings.GetByInternalUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user auth mapping: %w", err)
	}
	if mapping == nil {
		return nil, ErrUserNotFound
	}

	profile := &UserProfileAggregate{
		UserID:       user.ID,
		Email:        mapping.Email,
		Name:         user.Name,
		Market:       user.Market,
		KYCStatus:    user.KYCStatus,
		RegisteredAt: user.CreatedAt,
	}
	setUserProfileCache(ctx, profile)
	return profile, nil
}

func userProfileCacheKey(userID int64) string {
	return "user_profile:id:" + strconv.FormatInt(userID, 10)
}

func getUserProfileCache(ctx context.Context, userID int64) (*UserProfileAggregate, bool) {
	if !cacheredis.Available() {
		return nil, false
	}
	raw, err := cacheredis.Client.Get(ctx, userProfileCacheKey(userID)).Bytes()
	if err != nil {
		return nil, false
	}
	var profile UserProfileAggregate
	if err := json.Unmarshal(raw, &profile); err != nil {
		log.Logger.Warnw("invalid user profile cache entry", "userID", userID, "error", err)
		_ = cacheredis.Client.Del(ctx, userProfileCacheKey(userID)).Err()
		return nil, false
	}
	return &profile, true
}

func setUserProfileCache(ctx context.Context, profile *UserProfileAggregate) {
	if !cacheredis.Available() || profile == nil {
		return
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		log.Logger.Warnw("failed to marshal user profile for cache", "error", err)
		return
	}
	if err := cacheredis.Client.Set(ctx, userProfileCacheKey(profile.UserID), raw, userProfileCacheTTL).Err(); err != nil {
		log.Logger.Warnw("failed to set user profile cache", "userID", profile.UserID, "error", err)
	}
}

// InvalidateUserProfileCache drops the cached profile for userID (best-effort).
func InvalidateUserProfileCache(ctx context.Context, userID int64) {
	if !cacheredis.Available() || userID <= 0 {
		return
	}
	if err := cacheredis.Client.Del(ctx, userProfileCacheKey(userID)).Err(); err != nil {
		log.Logger.Warnw("failed to delete user profile cache", "userID", userID, "error", err)
	}
}
