package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao/mocks"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUserProfileService_GetProfile_masksEmailAndMapsKYC(t *testing.T) {
	createdAt := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(100)).Return(&model.User{
		ID: 100, Name: "alice", Language: "en", Market: "SG",
		KYCStatus: model.KYCStatusPassed, CreatedAt: createdAt,
	}, nil)
	svc := NewUserProfileService(users)

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
	svc := NewUserProfileService(users)

	profile, err := svc.GetProfile(context.Background(), 1, "a@b.com")

	require.NoError(t, err)
	require.Nil(t, profile)
}

func TestUserProfileService_GetProfile_propagatesError(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, errors.New("db down"))
	svc := NewUserProfileService(users)

	_, err := svc.GetProfile(context.Background(), 1, "a@b.com")

	require.Error(t, err)
}

func TestUserProfileService_GetUser_returnsUser(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(7)).Return(&model.User{ID: 7, Name: "bob"}, nil)
	svc := NewUserProfileService(users)

	user, err := svc.GetUser(context.Background(), 7)

	require.NoError(t, err)
	require.Equal(t, int64(7), user.ID)
	require.Equal(t, "bob", user.Name)
}

func TestUserProfileService_GetUser_notFound(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, nil)
	svc := NewUserProfileService(users)

	user, err := svc.GetUser(context.Background(), 1)

	require.NoError(t, err)
	require.Nil(t, user)
}

func TestUserProfileService_UpdateProfile_updatesLanguageAndUsername(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Name: "old", Market: "SG"}, nil)
	users.On("UpdateProfile", mock.Anything, int64(1), &model.User{
		Name:     "alice",
		Language: "zh-CN",
	}).Return(nil)
	svc := NewUserProfileService(users)

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
	svc := NewUserProfileService(users)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Market: "SG"})
	require.NoError(t, err)
}

func TestUserProfileService_UpdateProfile_rejectsMarketWhenAlreadySet(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Market: "SG"}, nil)
	svc := NewUserProfileService(users)

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
	svc := NewUserProfileService(users)

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
	svc := NewUserProfileService(users)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Language: "xx"})
	require.ErrorIs(t, err, ErrInvalidLanguage)
}

func TestUserProfileService_UpdateProfile_rejectsInvalidMarket(t *testing.T) {
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1}, nil)
	svc := NewUserProfileService(users)

	err := svc.UpdateProfile(context.Background(), 1, &data.UpdateUserProfileRequest{Market: "XX"})
	require.ErrorIs(t, err, ErrInvalidMarket)
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
			svc := NewUserProfileService(users)

			profile, err := svc.GetProfile(context.Background(), 1, tc.emailIn)

			require.NoError(t, err)
			require.Equal(t, tc.emailOut, profile.Email)
		})
	}
}
