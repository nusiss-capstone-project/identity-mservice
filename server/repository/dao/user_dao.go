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
		log.Logger.Errorf("Failed to get user by ID: %v", ret.Error)
		return nil, ret.Error
	}
	return &user, nil
}

func (dao *UserDaoImpl) CreateInTransaction(trx *gorm.DB, user *model.User) error {
	if dao.db == nil {
		return ErrDatabaseDisabled
	}
	ret := trx.Create(user)
	log.Logger.Infof("User created: %v", ret)
	return ret.Error
}
