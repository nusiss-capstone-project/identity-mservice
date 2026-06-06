package grpc

import (
	"context"

	"github.com/nusiss-capstone-project/identity-mservice/common/identitypb"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
)

type IdentityService struct {
	identitypb.UnimplementedIdentityServiceServer
}

func (s *IdentityService) SayHello(ctx context.Context, in *identitypb.HelloRequest) (*identitypb.HelloResponse, error) {
	log.Logger.Infof("Received: %v", in.GetName())
	return &identitypb.HelloResponse{Message: "Hello " + in.GetName()}, nil
}
