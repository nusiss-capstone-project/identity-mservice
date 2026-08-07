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

//go:generate env PATH=$HOME/go/bin:$PATH mockery --name UserDao --filename UserDao.go --output ./mocks --outpkg mocks
type UserDao interface {
	GetByID(ctx context.Context, id int64) (*model.User, error)
	CreateInTransaction(trx *gorm.DB, user *model.User) error
	UpdateKYCStatus(ctx context.Context, id int64, status string) error
	UpdateProfile(ctx context.Context, id int64, user *model.User) error
}

type UserDaoImpl struct {
	db *gorm.DB
}

var (
	userOnce sync.Once
	userDao  *UserDaoImpl
)

func GetUserDao() *UserDaoImpl {
	userOnce.Do(func() {
		if userDao == nil {
			userDao = &UserDaoImpl{db: repository.DB}
		}
	})
	return userDao
}

func (dao *UserDaoImpl) GetByID(ctx context.Context, id int64) (*model.User, error) {
	if dao.db == nil {
		return nil, ErrDatabaseDisabled
	}
	var user model.User
	ret := dao.db.WithContext(ctx).Where("id = ?", id).First(&user)
	if ret.Error != nil {
		if errors.Is(ret.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log.WithContext(ctx).Errorw("db read user by id failed", "user_id", id, "error", ret.Error)
		return nil, ret.Error
	}
	return &user, nil
}

func (dao *UserDaoImpl) CreateInTransaction(trx *gorm.DB, user *model.User) error {
	if dao.db == nil {
		return ErrDatabaseDisabled
	}
	ctx := statementContext(trx)
	ret := trx.Create(user)
	if ret.Error != nil {
		log.WithContext(ctx).Errorw("db write user create failed", "error", ret.Error)
		return ret.Error
	}
	log.WithContext(ctx).Infow("db write user created", "user_id", user.ID, "rows", ret.RowsAffected)
	return nil
}

func (dao *UserDaoImpl) UpdateKYCStatus(ctx context.Context, id int64, status string) error {
	if dao.db == nil {
		return ErrDatabaseDisabled
	}
	ret := dao.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Update("kyc_status", status)
	if ret.Error != nil {
		log.WithContext(ctx).Errorw("db write user kyc_status failed",
			"user_id", id, "kyc_status", status, "error", ret.Error)
		return ret.Error
	}
	log.WithContext(ctx).Infow("db write user kyc_status updated",
		"user_id", id, "kyc_status", status, "rows", ret.RowsAffected)
	return nil
}

func (dao *UserDaoImpl) UpdateProfile(ctx context.Context, id int64, user *model.User) error {
	if dao.db == nil {
		return ErrDatabaseDisabled
	}
	if user == nil {
		return nil
	}
	ret := dao.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Updates(user)
	if ret.Error != nil {
		log.WithContext(ctx).Errorw("db write user profile failed", "user_id", id, "error", ret.Error)
		return ret.Error
	}
	log.WithContext(ctx).Infow("db write user profile updated", "user_id", id, "rows", ret.RowsAffected)
	return nil
}

func statementContext(db *gorm.DB) context.Context {
	if db != nil && db.Statement != nil && db.Statement.Context != nil {
		return db.Statement.Context
	}
	return context.Background()
}
