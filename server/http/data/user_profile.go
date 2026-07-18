package data

// UserProfileVO is the user-facing profile payload.
type UserProfileVO struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	KYCChecked   bool   `json:"kycChecked"`
	RegisteredAt string `json:"registeredAt"`
}
