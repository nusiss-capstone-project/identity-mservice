package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	cacheredis "github.com/nusiss-capstone-project/identity-mservice/server/repository/redis"
	"github.com/nusiss-capstone-project/identity-mservice/server/util"
)

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrMarketAlreadySet = errors.New("market already set")
	ErrInvalidMarket    = errors.New("invalid market")
	ErrInvalidLanguage  = errors.New("invalid language")
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

// UserProfileService serves HTTP user-profile and gRPC GetUserProfile.
type UserProfileService interface {
	GetProfile(ctx context.Context, userID int64, email string) (*data.UserProfileVO, error)
	UpdateProfile(ctx context.Context, userID int64, req *data.UpdateUserProfileRequest) error
	GetUserProfile(ctx context.Context, userID int64) (*UserProfileAggregate, error)
}

type UserProfileServiceImpl struct {
	users    dao.UserDao
	mappings dao.UserAuthMappingDao
}

var (
	userProfileServiceOnce sync.Once
	userProfileServiceInst *UserProfileServiceImpl
)

func NewUserProfileService(users dao.UserDao, mappings dao.UserAuthMappingDao) *UserProfileServiceImpl {
	return &UserProfileServiceImpl{users: users, mappings: mappings}
}

func GetUserProfileService() *UserProfileServiceImpl {
	userProfileServiceOnce.Do(func() {
		userProfileServiceInst = NewUserProfileService(dao.GetUserDao(), dao.GetUserAuthMappingDao())
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

// GetUserProfile joins users + auth mapping for internal/gRPC callers (Redis-cached).
func (s *UserProfileServiceImpl) GetUserProfile(ctx context.Context, userID int64) (*UserProfileAggregate, error) {
	if userID <= 0 {
		return nil, ErrInvalidArgument
	}
	if cached, ok := getUserProfileCache(ctx, userID); ok {
		log.WithContext(ctx).Infof("get user profile from cache: %v", cached)
		return cached, nil
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		log.WithContext(ctx).Infof("get user error: %v", err)
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user == nil {
		log.WithContext(ctx).Infof("user not found: %v", userID)
		return nil, ErrUserNotFound
	}
	mapping, err := s.mappings.GetByInternalUserID(ctx, userID)
	if err != nil {
		log.WithContext(ctx).Infof("get user auth mapping error: %v", err)
		return nil, fmt.Errorf("get user auth mapping: %w", err)
	}
	if mapping == nil {
		log.WithContext(ctx).Infof("user auth mapping not found: %v", userID)
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
	log.WithContext(ctx).Infof("set user profile to cache: %v", profile)
	return profile, nil
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

	update, err := buildProfileUpdate(user, req)
	if err != nil {
		return err
	}
	if update == nil {
		return nil
	}
	if err := s.users.UpdateProfile(ctx, userID, update); err != nil {
		return err
	}
	InvalidateUserProfileCache(ctx, userID)
	return nil
}

func buildProfileUpdate(user *model.User, req *data.UpdateUserProfileRequest) (*model.User, error) {
	update := &model.User{}
	hasUpdate := applyUsernameUpdate(update, req.Username)

	applied, err := applyLanguageUpdate(update, req.Language)
	if err != nil {
		return nil, err
	}
	hasUpdate = hasUpdate || applied

	applied, err = applyMarketUpdate(update, user.Market, req.Market)
	if err != nil {
		return nil, err
	}
	hasUpdate = hasUpdate || applied

	if !hasUpdate {
		return nil, nil
	}
	return update, nil
}

func applyUsernameUpdate(update *model.User, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	update.Name = username
	return true
}

func applyLanguageUpdate(update *model.User, language string) (bool, error) {
	language = strings.TrimSpace(language)
	if language == "" {
		return false, nil
	}
	if !data.IsValidLanguage(language) {
		return false, ErrInvalidLanguage
	}
	update.Language = language
	return true, nil
}

func applyMarketUpdate(update *model.User, existingMarket, market string) (bool, error) {
	market = strings.TrimSpace(market)
	if market == "" {
		return false, nil
	}
	if !data.IsValidMarket(market) {
		return false, ErrInvalidMarket
	}
	existing := strings.TrimSpace(existingMarket)
	if existing != "" && existing != market {
		return false, ErrMarketAlreadySet
	}
	if existing != "" {
		return false, nil
	}
	update.Market = market
	return true, nil
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
