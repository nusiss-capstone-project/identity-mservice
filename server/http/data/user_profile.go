package data

// UserProfileVO is the user-facing profile payload.
type UserProfileVO struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	Language     string `json:"language"`
	Market       string `json:"market"`
	KYCChecked   bool   `json:"kycChecked"`
	RegisteredAt string `json:"registeredAt"`
}

// UpdateUserProfileRequest is the body for PUT /web/user-profile.
// Empty fields are ignored (partial update).
type UpdateUserProfileRequest struct {
	Username string `json:"username"`
	Language string `json:"language"`
	Market   string `json:"market"`
}
