package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/nusiss-capstone-project/identity-mservice/server/http/data"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao/mocks"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type fakeTxBeginner struct{}

func (fakeTxBeginner) Transaction(fc func(tx *gorm.DB) error, _ ...*sql.TxOptions) error {
	return fc(nil)
}

func clerkUserData() *data.ClerkCallbackData {
	return &data.ClerkCallbackData{
		ID: "user_abc",
		EmailAddresses: []data.ClerkEmailAddress{
			{EmailAddress: "alice@example.com"},
		},
	}
}

func TestUserMappingService_CreateUser_createsMapping(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	mappings.On("GetByClerkUserID", mock.Anything, "user_abc").Return(nil, nil)
	mappings.On("GetByEmail", mock.Anything, "alice@example.com").Return(nil, nil)
	users.On("CreateInTransaction", mock.Anything, mock.AnythingOfType("*model.User")).
		Run(func(args mock.Arguments) {
			u := args.Get(1).(*model.User)
			u.ID = 100
		}).
		Return(nil)
	mappings.On("CreateInTransaction", mock.Anything, mock.MatchedBy(func(m *model.UserAuthMapping) bool {
		return m.ClerkUserID == "user_abc" &&
			m.Email == "alice@example.com" &&
			m.InternalUserID == 100 &&
			m.Role == model.RoleUser
	})).Return(nil)

	svc := newUserMappingService(mappings, users, fakeTxBeginner{})
	err := svc.CreateUser(context.Background(), clerkUserData())

	require.NoError(t, err)
	users.AssertExpectations(t)
	mappings.AssertExpectations(t)
}

func TestUserMappingService_CreateUser_skipsWhenClerkUserExists(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	mappings.On("GetByClerkUserID", mock.Anything, "user_abc").Return(&model.UserAuthMapping{
		ClerkUserID: "user_abc",
	}, nil)

	svc := newUserMappingService(mappings, users, fakeTxBeginner{})
	err := svc.CreateUser(context.Background(), clerkUserData())

	require.NoError(t, err)
	users.AssertNotCalled(t, "CreateInTransaction", mock.Anything, mock.Anything)
	mappings.AssertNotCalled(t, "CreateInTransaction", mock.Anything, mock.Anything)
}

func TestUserMappingService_CreateUser_skipsWhenEmailExists(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	mappings.On("GetByClerkUserID", mock.Anything, "user_abc").Return(nil, nil)
	mappings.On("GetByEmail", mock.Anything, "alice@example.com").Return(&model.UserAuthMapping{
		Email: "alice@example.com",
	}, nil)

	svc := newUserMappingService(mappings, users, fakeTxBeginner{})
	err := svc.CreateUser(context.Background(), clerkUserData())

	require.NoError(t, err)
	users.AssertNotCalled(t, "CreateInTransaction", mock.Anything, mock.Anything)
	mappings.AssertNotCalled(t, "CreateInTransaction", mock.Anything, mock.Anything)
}

func TestUserMappingService_CreateUser_propagatesLookupError(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	mappings.On("GetByClerkUserID", mock.Anything, "user_abc").Return(nil, errors.New("db down"))

	svc := newUserMappingService(mappings, users, fakeTxBeginner{})
	err := svc.CreateUser(context.Background(), clerkUserData())

	require.Error(t, err)
}

func TestUserMappingService_CreateUser_propagatesCreateError(t *testing.T) {
	users := new(mocks.UserDao)
	mappings := new(mocks.UserAuthMappingDao)
	mappings.On("GetByClerkUserID", mock.Anything, "user_abc").Return(nil, nil)
	mappings.On("GetByEmail", mock.Anything, "alice@example.com").Return(nil, nil)
	users.On("CreateInTransaction", mock.Anything, mock.AnythingOfType("*model.User")).
		Return(errors.New("insert failed"))

	svc := newUserMappingService(mappings, users, fakeTxBeginner{})
	err := svc.CreateUser(context.Background(), clerkUserData())

	require.Error(t, err)
}

var _ repository.TxBeginner = fakeTxBeginner{}
