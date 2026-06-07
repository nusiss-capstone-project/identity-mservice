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

func TestUserProfileService_GetProfile_masksEmailAndMapsKYC(t *testing.T) {
	createdAt := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	users := new(mocks.UserDao)
	users.On("GetByID", mock.Anything, int64(100)).Return(&model.User{
		ID: 100, Name: "alice", KYCStatus: model.KYCStatusPassed, CreatedAt: createdAt,
	}, nil)
	svc := NewUserProfileService(users)

	profile, err := svc.GetProfile(context.Background(), 100, "alice@example.com")

	require.NoError(t, err)
	require.Equal(t, "alice", profile.Username)
	require.Equal(t, "a***e@example.com", profile.Email)
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
