package repository

import (
	"database/sql"
	"fmt"

	"github.com/__TEMPLATE_ORG__/__TEMPLATE_REPO__/server/config"
	"github.com/__TEMPLATE_ORG__/__TEMPLATE_REPO__/server/repository/model"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	DB  *gorm.DB
	err error
)

type TxBeginner interface {
	Transaction(fc func(tx *gorm.DB) error, opts ...*sql.TxOptions) error
}

var _ TxBeginner = (*gorm.DB)(nil) // Compile-time interface check

func Init() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.Config.MySQLConfig.UserName,
		config.Config.MySQLConfig.Password,
		config.Config.MySQLConfig.Host,
		config.Config.MySQLConfig.Port,
		config.Config.MySQLConfig.DBName,
	)
	DB, err = gorm.Open(mysql.Open(dsn),
		&gorm.Config{
			PrepareStmt:            true,
			SkipDefaultTransaction: true,
		},
	)
	if err != nil {
		panic(err)
	}
	err = DB.AutoMigrate(
		&model.Item{},
	)
	if err != nil {
		panic(err)
	}
}
