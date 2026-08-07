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
	GetByInternalUserID(ctx context.Context, internalUserID int64) (*model.UserAuthMapping, error)
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
	if cached, ok := dao.getMappingFromCache(ctx, clerkUserID); ok {
		log.WithContext(ctx).Infow("user auth mapping cache hit", "clerk_user_id", clerkUserID)
		return cached, nil
	}
	if dao.db == nil {
		return nil, ErrDatabaseDisabled
	}
	var row model.UserAuthMapping
	ret := dao.db.WithContext(ctx).Where("clerk_user_id = ?", clerkUserID).First(&row)
	if ret.Error != nil {
		if errors.Is(ret.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log.WithContext(ctx).Errorw("db read user auth mapping by clerk id failed",
			"clerk_user_id", clerkUserID, "error", ret.Error)
		return nil, ret.Error
	}
	dao.setMappingCache(ctx, &row)
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
		log.WithContext(ctx).Errorw("db read user auth mapping by email failed", "error", ret.Error)
		return nil, ret.Error
	}
	return &row, nil
}

func (dao *UserAuthMappingDaoImpl) GetByInternalUserID(ctx context.Context, internalUserID int64) (*model.UserAuthMapping, error) {
	if dao.db == nil {
		return nil, ErrDatabaseDisabled
	}
	if internalUserID <= 0 {
		return nil, nil
	}
	var row model.UserAuthMapping
	ret := dao.db.WithContext(ctx).Where("internal_user_id = ?", internalUserID).First(&row)
	if ret.Error != nil {
		if errors.Is(ret.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log.WithContext(ctx).Errorw("db read user auth mapping by internal user id failed",
			"user_id", internalUserID, "error", ret.Error)
		return nil, ret.Error
	}
	return &row, nil
}

func (dao *UserAuthMappingDaoImpl) CreateInTransaction(trx *gorm.DB, userAuthMapping *model.UserAuthMapping) error {
	if dao.db == nil {
		return ErrDatabaseDisabled
	}
	ctx := statementContext(trx)
	if userAuthMapping != nil {
		dao.deleteMappingCache(ctx, userAuthMapping.ClerkUserID)
	}
	ret := trx.Create(userAuthMapping)
	if ret.Error != nil {
		log.WithContext(ctx).Errorw("db write user auth mapping create failed", "error", ret.Error)
		return ret.Error
	}
	fields := []any{"rows", ret.RowsAffected}
	if userAuthMapping != nil {
		fields = append(fields,
			"user_id", userAuthMapping.InternalUserID,
			"clerk_user_id", userAuthMapping.ClerkUserID,
		)
		dao.deleteMappingCache(ctx, userAuthMapping.ClerkUserID)
	}
	log.WithContext(ctx).Infow("db write user auth mapping created", fields...)
	return nil
}
