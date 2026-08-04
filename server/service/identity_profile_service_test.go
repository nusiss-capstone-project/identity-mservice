package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao/mocks"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestIdentityProfileService_GetUserProfile_joinsUserAndMapping(t *testing.T) {
	createdAt := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	users.On("GetByID", mock.Anything, int64(42)).Return(&model.User{
		ID: 42, Name: "alice", Market: "SG", KYCStatus: model.KYCStatusPassed, CreatedAt: createdAt,
	}, nil)
	mappings.On("GetByInternalUserID", mock.Anything, int64(42)).Return(&model.UserAuthMapping{
		InternalUserID: 42, Email: "alice@example.com",
	}, nil)

	svc := newIdentityProfileService(users, mappings)
	profile, err := svc.GetUserProfile(context.Background(), 42)

	require.NoError(t, err)
	require.Equal(t, int64(42), profile.UserID)
	require.Equal(t, "alice@example.com", profile.Email)
	require.Equal(t, "alice", profile.Name)
	require.Equal(t, "SG", profile.Market)
	require.Equal(t, model.KYCStatusPassed, profile.KYCStatus)
	require.Equal(t, createdAt, profile.RegisteredAt)
}

func TestIdentityProfileService_GetUserProfile_invalidUserID(t *testing.T) {
	svc := newIdentityProfileService(new(mocks.UserDao), new(mocks.UserAuthMappingDao))
	_, err := svc.GetUserProfile(context.Background(), 0)
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestIdentityProfileService_GetUserProfile_userNotFound(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, nil)

	svc := newIdentityProfileService(users, mappings)
	_, err := svc.GetUserProfile(context.Background(), 1)
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestIdentityProfileService_GetUserProfile_mappingNotFound(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(&model.User{ID: 1, Name: "x"}, nil)
	mappings.On("GetByInternalUserID", mock.Anything, int64(1)).Return(nil, nil)

	svc := newIdentityProfileService(users, mappings)
	_, err := svc.GetUserProfile(context.Background(), 1)
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestIdentityProfileService_GetUserProfile_propagatesUserLookupError(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	users.On("GetByID", mock.Anything, int64(1)).Return(nil, errors.New("db down"))

	svc := newIdentityProfileService(users, mappings)
	_, err := svc.GetUserProfile(context.Background(), 1)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrUserNotFound)
}
