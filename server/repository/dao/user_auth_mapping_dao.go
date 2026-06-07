package dao

import (
	"context"
	"errors"
	"sync"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"gorm.io/gorm"
)

//go:generate env PATH=$HOME/go/bin:$PATH mockery --name UserAuthMappingDao --filename UserAuthMappingDao.go --output ./mocks --outpkg mocks
type UserAuthMappingDao interface {
	GetByClerkUserID(ctx context.Context, clerkUserID string) (*model.UserAuthMapping, error)
	GetByEmail(ctx context.Context, email string) (*model.UserAuthMapping, error)
	CreateInTransaction(trx *gorm.DB, userAuthMapping *model.UserAuthMapping) error
}

type UserAuthMappingDaoImpl struct {
	db *gorm.DB
}

var (
	userAuthMappingOnce sync.Once
	userAuthMappingDao  *UserAuthMappingDaoImpl
)

func GetUserAuthMappingDao() *UserAuthMappingDaoImpl {
	userAuthMappingOnce.Do(func() {
		if userAuthMappingDao == nil {
			userAuthMappingDao = &UserAuthMappingDaoImpl{db: repository.DB}
		}
	})
	return userAuthMappingDao
}

func (dao *UserAuthMappingDaoImpl) GetByClerkUserID(ctx context.Context, clerkUserID string) (*model.UserAuthMapping, error) {
	if dao.db == nil {
		return nil, ErrDatabaseDisabled
	}
	var row model.UserAuthMapping
	ret := dao.db.WithContext(ctx).Where("clerk_user_id = ?", clerkUserID).First(&row)
	if ret.Error != nil {
		if errors.Is(ret.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log.Logger.Errorf("Failed to get user auth mapping: %v", ret.Error)
		return nil, ret.Error
	}
	return &row, nil
}

func (dao *UserAuthMappingDaoImpl) GetByEmail(ctx context.Context, email string) (*model.UserAuthMapping, error) {
	if dao.db == nil {
		return nil, ErrDatabaseDisabled
	}
	var row model.UserAuthMapping
	ret := dao.db.WithContext(ctx).Where("email = ?", email).First(&row)
	if ret.Error != nil {
		if errors.Is(ret.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log.Logger.Errorf("Failed to get user auth mapping: %v", ret.Error)
		return nil, ret.Error
	}
	return &row, nil
}

func (dao *UserAuthMappingDaoImpl) CreateInTransaction(trx *gorm.DB, userAuthMapping *model.UserAuthMapping) error {
	if dao.db == nil {
		return ErrDatabaseDisabled
	}
	ret := trx.Create(userAuthMapping)
	log.Logger.Infof("User auth mapping created: %v", ret)
	return ret.Error
}
