package model

import "time"

// User maps to table users.
type User struct {
	ID        int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Name      string    `gorm:"column:name;size:255"`
	Market    string    `gorm:"column:market;size:64"`
	Segment   string    `gorm:"column:segment;size:64"`
	KYCStatus string    `gorm:"column:kyc_status;size:32"`
	RiskLevel string    `gorm:"column:risk_level;size:32"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (User) TableName() string {
	return "users"
}
