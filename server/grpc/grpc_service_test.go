package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/common/identitypb"
	"github.com/nusiss-capstone-project/identity-mservice/server/service"
	"github.com/stretchr/testify/require"
)

type fakeUserProfileLookup struct {
	profile *service.UserProfileAggregate
	err     error
}

func (f fakeUserProfileLookup) GetUserProfile(context.Context, int64) (*service.UserProfileAggregate, error) {
	return f.profile, f.err
}

func TestIdentityService_GetUserProfile_success(t *testing.T) {
	createdAt := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	svc := NewIdentityService(fakeUserProfileLookup{
		profile: &service.UserProfileAggregate{
			UserID: 42, Email: "a@b.com", Name: "alice", Market: "SG",
			KYCStatus: "PASSED", RegisteredAt: createdAt,
		},
	})

	resp, err := svc.GetUserProfile(context.Background(), &identitypb.GetUserProfileRequest{UserId: 42})
	require.NoError(t, err)
	require.Equal(t, identitypb.ErrorCode_ERROR_CODE_OK, resp.GetBaseInfo().GetCode())
	require.Equal(t, int64(42), resp.GetUserId())
	require.Equal(t, "alice", resp.GetName())
	require.Equal(t, createdAt.Unix(), resp.GetRegisteredAt())
}

func TestIdentityService_GetUserProfile_userNotFound(t *testing.T) {
	svc := NewIdentityService(fakeUserProfileLookup{err: service.ErrUserNotFound})
	resp, err := svc.GetUserProfile(context.Background(), &identitypb.GetUserProfileRequest{UserId: 1})
	require.NoError(t, err)
	require.Equal(t, identitypb.ErrorCode_ERROR_CODE_USER_NOT_FOUND, resp.GetBaseInfo().GetCode())
}

func TestIdentityService_GetUserProfile_invalidArgument(t *testing.T) {
	svc := NewIdentityService(fakeUserProfileLookup{err: service.ErrInvalidArgument})
	resp, err := svc.GetUserProfile(context.Background(), &identitypb.GetUserProfileRequest{UserId: 0})
	require.NoError(t, err)
	require.Equal(t, identitypb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.GetBaseInfo().GetCode())
}

func TestIdentityService_GetUserProfile_internalError(t *testing.T) {
	svc := NewIdentityService(fakeUserProfileLookup{err: errors.New("db down")})
	resp, err := svc.GetUserProfile(context.Background(), &identitypb.GetUserProfileRequest{UserId: 1})
	require.NoError(t, err)
	require.Equal(t, identitypb.ErrorCode_ERROR_CODE_INTERNAL, resp.GetBaseInfo().GetCode())
}
