package grpc

import (
	"context"
	"errors"

	"github.com/nusiss-capstone-project/identity-mservice/common/identitypb"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/service"
)

type IdentityService struct {
	identitypb.UnimplementedIdentityServiceServer
	profiles service.IdentityProfileService
}

func NewIdentityService(profiles service.IdentityProfileService) *IdentityService {
	if profiles == nil {
		profiles = service.GetIdentityProfileService()
	}
	return &IdentityService{profiles: profiles}
}

func (s *IdentityService) SayHello(ctx context.Context, in *identitypb.HelloRequest) (*identitypb.HelloResponse, error) {
	log.Logger.Infof("Received: %v", in.GetName())
	return &identitypb.HelloResponse{Message: "Hello " + in.GetName()}, nil
}

func (s *IdentityService) GetUserProfile(ctx context.Context, in *identitypb.GetUserProfileRequest) (*identitypb.GetUserProfileResponse, error) {
	profile, err := s.profiles.GetUserProfile(ctx, in.GetUserId())
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidArgument):
			return &identitypb.GetUserProfileResponse{
				BaseInfo: &identitypb.BaseResponseInfo{
					Code:    identitypb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					Message: "userId must be positive",
				},
			}, nil
		case errors.Is(err, service.ErrUserNotFound):
			return &identitypb.GetUserProfileResponse{
				BaseInfo: &identitypb.BaseResponseInfo{
					Code:    identitypb.ErrorCode_ERROR_CODE_USER_NOT_FOUND,
					Message: "user not found",
				},
			}, nil
		default:
			log.WithContext(ctx).Errorf("GetUserProfile failed userId=%d: %v", in.GetUserId(), err)
			return &identitypb.GetUserProfileResponse{
				BaseInfo: &identitypb.BaseResponseInfo{
					Code:    identitypb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: "internal error",
				},
			}, nil
		}
	}
	return &identitypb.GetUserProfileResponse{
		UserId:       profile.UserID,
		Email:        profile.Email,
		Name:         profile.Name,
		Market:       profile.Market,
		KycStatus:    profile.KYCStatus,
		RegisteredAt: profile.RegisteredAt.Unix(),
		BaseInfo: &identitypb.BaseResponseInfo{
			Code:    identitypb.ErrorCode_ERROR_CODE_OK,
			Message: "ok",
		},
	}, nil
}
