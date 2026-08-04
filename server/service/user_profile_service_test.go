package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao/mocks"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	cacheredis "github.com/nusiss-capstone-project/identity-mservice/server/repository/redis"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestUserProfileService(users *mocks.UserDao, mappings *mocks.UserAuthMappingDao) *UserProfileServiceImpl {
	if mappings == nil {
		mappings = new(mocks.UserAuthMappingDao)
	}
	return NewUserProfileService(users, mappings)
}

func TestUserProfileService_GetProfile_masksEmailAndMapsKYC(t *testing.T) {
	createdAt := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(100)).Return(&model.User{
		ID: 100, Name: "alice", Language: "en", Market: "SG",
		KYCStatus: model.KYCStatusPassed, CreatedAt: createdAt,
	}, nil)
	svc := newTestUserProfileService(users, nil)

	profile, err := svc.GetProfile(context.Background(), 100, "alice@example.com")

	require.NoError(t, err)
	require.Equal(t, "alice", profile.Username)
	require.Equal(t, "a***e@example.com", profile.Email)
	require.Equal(t, "en", profile.Language)
	require.Equal(t, "SG", profile.Market)
	require.True(t, profile.KYCChecked)
	require.Equal(t, createdAt.Format(time.RFC3339), profile.RegisteredAt)
}

func TestUserProfileService_GetProfile_notFound(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, nil)
	svc := newTestUserProfileService(users, nil)

	profile, err := svc.GetProfile(context.Background(), 1, "a@b.com")

	require.NoError(t, err)
	require.Nil(t, profile)
}

func TestUserProfileService_GetProfile_propagatesError(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, errors.New("db down"))
	svc := newTestUserProfileService(users, nil)

	_, err := svc.GetProfile(context.Background(), 1, "a@b.com")

	require.Error(t, err)
}

func TestUserProfileService_GetUser_returnsUser(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(7)).Return(&model.User{ID: 7, Name: "bob"}, nil)
	svc := newTestUserProfileService(users, nil)

	user, err := svc.GetUser(context.Background(), 7)

	require.NoError(t, err)
	require.Equal(t, int64(7), user.ID)
	require.Equal(t, "bob", user.Name)
}

func TestUserProfileService_GetUser_notFound(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, nil)
	svc := newTestUserProfileService(users, nil)

	user, err := svc.GetUser(context.Background(), 1)

	require.NoError(t, err)
	require.Nil(t, user)
}

func TestUserProfileService_GetUserProfile_joinsUserAndMapping(t *testing.T) {
	createdAt := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	users.On("GetByID", mock.Anything, int64(42)).Return(&model.User{
		ID: 42, Name: "alice", Market: "SG", KYCStatus: model.KYCStatusPassed, CreatedAt: createdAt,
	}, nil)
	mappings.On("GetByInternalUserID", mock.Anything, int64(42)).Return(&model.UserAuthMapping{
		InternalUserID: 42, Email: "alice@example.com",
	}, nil)

	svc := newTestUserProfileService(users, mappings)
	profile, err := svc.GetUserProfile(context.Background(), 42)

	require.NoError(t, err)
	require.Equal(t, int64(42), profile.UserID)
	require.Equal(t, "alice@example.com", profile.Email)
	require.Equal(t, "alice", profile.Name)
	require.Equal(t, "SG", profile.Market)
	require.Equal(t, model.KYCStatusPassed, profile.KYCStatus)
	require.Equal(t, createdAt, profile.RegisteredAt)
}

func TestUserProfileService_GetUserProfile_invalidUserID(t *testing.T) {
	svc := newTestUserProfileService(new(mocks.UserDao), new(mocks.UserAuthMappingDao))
	_, err := svc.GetUserProfile(context.Background(), 0)
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestUserProfileService_GetUserProfile_userNotFound(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, nil)

	svc := newTestUserProfileService(users, nil)
	_, err := svc.GetUserProfile(context.Background(), 1)
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestUserProfileService_GetUserProfile_mappingNotFound(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Name: "x"}, nil)
	mappings.On("GetByInternalUserID", mock.Anything, int64(1)).Return(nil, nil)

	svc := newTestUserProfileService(users, mappings)
	_, err := svc.GetUserProfile(context.Background(), 1)
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestUserProfileService_GetUserProfile_propagatesUserLookupError(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, errors.New("db down"))

	svc := newTestUserProfileService(users, nil)
	_, err := svc.GetUserProfile(context.Background(), 1)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrUserNotFound)
}

func TestUserProfileService_GetUserProfile_propagatesMappingLookupError(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1}, nil)
	mappings.On("GetByInternalUserID", mock.Anything, int64(1)).Return(nil, errors.New("mapping db down"))

	svc := newTestUserProfileService(users, mappings)
	_, err := svc.GetUserProfile(context.Background(), 1)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrUserNotFound)
}

func TestUserProfileService_UpdateProfile_updatesLanguageAndUsername(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Name: "old", Market: "SG"}, nil)
	users.On("UpdateProfile", mock.Anything, int64(1), &model.User{
		Name:     "alice",
		Language: "zh-CN",
	}).Return(nil)
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{
		Username: "alice",
		Language: "zh-CN",
	})

	require.NoError(t, err)
	users.AssertExpectations(t)
}

func TestUserProfileService_UpdateProfile_setsMarketOnce(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Market: ""}, nil)
	users.On("UpdateProfile", mock.Anything, int64(1), &model.User{Market: "SG"}).Return(nil)
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Market: "SG"})
	require.NoError(t, err)
}

func TestUserProfileService_UpdateProfile_rejectsMarketWhenAlreadySet(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Market: "SG"}, nil)
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Market: "HK"})
	require.ErrorIs(t, err, ErrMarketAlreadySet)
	users.AssertNotCalled(t, "UpdateProfile", mock.Anything, mock.Anything, mock.Anything)
}

func TestUserProfileService_UpdateProfile_sameMarketAllowsOtherFields(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Name: "old", Market: "SG"}, nil)
	users.On("UpdateProfile", mock.Anything, int64(1), &model.User{
		Name:     "alice",
		Language: "zh-CN",
	}).Return(nil)
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{
		Username: "alice",
		Language: "zh-CN",
		Market:   "SG",
	})
	require.NoError(t, err)
	users.AssertExpectations(t)
}

func TestUserProfileService_UpdateProfile_rejectsInvalidLanguage(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1}, nil)
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Language: "xx"})
	require.ErrorIs(t, err, ErrInvalidLanguage)
}

func TestUserProfileService_UpdateProfile_rejectsInvalidMarket(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1}, nil)
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Market: "XX"})
	require.ErrorIs(t, err, ErrInvalidMarket)
}

func TestUserProfileService_UpdateProfile_nilRequest(t *testing.T) {
	svc := newTestUserProfileService(new(mocks.UserDao), nil)
	err := svc.UpdateProfile(context.Background(), 1, nil)
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestUserProfileService_UpdateProfile_userNotFound(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, nil)
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Username: "alice"})
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestUserProfileService_UpdateProfile_noopWhenNoFields(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Market: "SG"}, nil)
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{})
	require.NoError(t, err)
	users.AssertNotCalled(t, "UpdateProfile", mock.Anything, mock.Anything, mock.Anything)
}

func TestUserProfileService_UpdateProfile_propagatesDAOError(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1}, nil)
	users.On("UpdateProfile", mock.Anything, int64(1), &model.User{Name: "alice"}).Return(errors.New("update failed"))
	svc := newTestUserProfileService(users, nil)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Username: "alice"})
	require.ErrorContains(t, err, "update failed")
}

func TestInvalidateUserProfileCache_noOpWhenRedisUnavailableOrInvalidID(t *testing.T) {
	// Redis is typically unavailable in unit tests; both paths should be safe no-ops.
	InvalidateUserProfileCache(context.Background(), 0)
	InvalidateUserProfileCache(context.Background(), 42)
}

func TestUserProfileCacheKey(t *testing.T) {
	require.Equal(t, "user_profile:id:42", userProfileCacheKey(42))
}

func TestUserProfileService_GetProfile_masksEmailVariants(t *testing.T) {
	createdAt := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		emailIn  string
		emailOut string
	}{
		{name: "standard", emailIn: "alice@example.com", emailOut: "a***e@example.com"},
		{name: "short local", emailIn: "ab@c.com", emailOut: "a*@c.com"},
		{name: "single char local", emailIn: "a@x.com", emailOut: "*@x.com"},
		{name: "no at sign", emailIn: "secret", emailOut: "s***t"},
		{name: "empty", emailIn: "  ", emailOut: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := new(mocks.UserDao)
			users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{
				ID: 1, Name: "u", KYCStatus: model.KYCStatusPending, CreatedAt: createdAt,
			}, nil)
			svc := newTestUserProfileService(users, nil)

			profile, err := svc.GetProfile(context.Background(), 1, tc.emailIn)

			require.NoError(t, err)
			require.Equal(t, tc.emailOut, profile.Email)
			require.False(t, profile.KYCChecked)
		})
	}
}

func withTestRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	prev := cacheredis.Client
	cacheredis.Client = client
	t.Cleanup(func() {
		cacheredis.Client = prev
		_ = client.Close()
	})
	return mr
}

func TestUserProfileService_GetUserProfile_cacheHit(t *testing.T) {
	withTestRedis(t)
	createdAt := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	users.On("GetByID", mock.Anything, int64(42)).Return(&model.User{
		ID: 42, Name: "alice", Market: "SG", KYCStatus: model.KYCStatusPassed, CreatedAt: createdAt,
	}, nil).Once()
	mappings.On("GetByInternalUserID", mock.Anything, int64(42)).Return(&model.UserAuthMapping{
		InternalUserID: 42, Email: "alice@example.com",
	}, nil).Once()

	svc := newTestUserProfileService(users, mappings)
	first, err := svc.GetUserProfile(context.Background(), 42)
	require.NoError(t, err)

	second, err := svc.GetUserProfile(context.Background(), 42)
	require.NoError(t, err)
	require.Equal(t, first, second)
	users.AssertNumberOfCalls(t, "GetByID", 1)
	mappings.AssertNumberOfCalls(t, "GetByInternalUserID", 1)
}

func TestGetUserProfileCache_clearsInvalidJSON(t *testing.T) {
	mr := withTestRedis(t)
	require.NoError(t, mr.Set(userProfileCacheKey(7), "{not-json"))

	profile, ok := getUserProfileCache(context.Background(), 7)
	require.False(t, ok)
	require.Nil(t, profile)
	require.False(t, mr.Exists(userProfileCacheKey(7)))
}

func TestInvalidateUserProfileCache_deletesCachedProfile(t *testing.T) {
	mr := withTestRedis(t)
	require.NoError(t, mr.Set(userProfileCacheKey(9), `{"userId":9}`))

	InvalidateUserProfileCache(context.Background(), 9)
	require.False(t, mr.Exists(userProfileCacheKey(9)))
}

func TestSetUserProfileCache_noOpWhenNil(t *testing.T) {
	withTestRedis(t)
	setUserProfileCache(context.Background(), nil)
}
