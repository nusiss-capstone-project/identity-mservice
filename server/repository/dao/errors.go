package dao

import (
	"errors"

	"gorm.io/gorm"
)

var ErrDatabaseDisabled = errors.New("database is disabled or not initialized")

func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}
