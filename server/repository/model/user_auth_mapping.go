package model

import "time"

// UserAuthMapping maps a Clerk identity to an internal user and role.
type UserAuthMapping struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	ClerkUserID    string    `gorm:"column:clerk_user_id;size:128;uniqueIndex;not null"`
	Email          string    `gorm:"column:email;size:255"`
	InternalUserID int64     `gorm:"column:internal_user_id;not null;index"`
	Role           string    `gorm:"column:role;size:32;not null"`
	CreatedAt      time.Time `gorm:"column:created_at"`
	UpdatedAt      time.Time `gorm:"column:updated_at"`
}

func (UserAuthMapping) TableName() string {
	return "user_auth_mapping"
}
