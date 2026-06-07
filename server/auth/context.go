package auth

import "context"

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

type contextKey struct{}

// User is the authenticated request identity.
type User struct {
	InternalUserID int64
	ClerkUserID    string
	Email          string
	Role           string
}

// WithUser stores the authenticated user in context.
func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, contextKey{}, user)
}

// GetUser returns the authenticated user from context.
func GetUser(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(contextKey{}).(*User)
	return user, ok && user != nil
}

// GetUserID returns the internal user id from context.
func GetUserID(ctx context.Context) (int64, bool) {
	user, ok := GetUser(ctx)
	if !ok {
		return 0, false
	}
	return user.InternalUserID, true
}
