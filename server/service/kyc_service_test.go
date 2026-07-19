package service

import (
	"context"
	"errors"
	urlpkg "net/url"
	"testing"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/config"
	"github.com/nusiss-capstone-project/identity-mservice/server/proxy"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao/mocks"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeSingpassProxy struct {
	token    string
	tokenErr error
	info     *proxy.UserInfo
	infoErr  error
}

func (f *fakeSingpassProxy) GetAccessToken(_ context.Context, _ string) (string, error) {
	return f.token, f.tokenErr
}

func (f *fakeSingpassProxy) GetUserInfo(_ context.Context, _ string) (*proxy.UserInfo, error) {
	return f.info, f.infoErr
}

func seedState(store KYCStateStore, state string, userID int64, email string) {
	store.Save(state, KYCPending{InternalUserID: userID, Email: email})
}

func TestKYCService_StartSingpassLogin_savesStateAndReturnsURL(t *testing.T) {
	prev := config.Config.SingpassConfig
	config.Config.SingpassConfig = &config.SingpassConfig{
		RedirectURI: "http://localhost/callback",
		Scope:       "openid",
		IssuerURL:   "https://idp.example/singpass/v2",
	}
	t.Cleanup(func() { config.Config.SingpassConfig = prev })
	t.Setenv("SINGPASS_CLIENT_ID", "client-id")

	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	svc := newKYCService(&fakeSingpassProxy{}, users, store)

	url, err := svc.StartSingpassLogin(context.Background(), 42, "alice@example.com")
	require.NoError(t, err)
	require.Contains(t, url, "https://idp.example/singpass/v2/auth?")
	require.Contains(t, url, "client_id=client-id")

	// Extract state from authorize URL and ensure callback can consume it.
	u, err := urlpkg.Parse(url)
	require.NoError(t, err)
	state := u.Query().Get("state")
	require.NotEmpty(t, state)
	pending, ok := store.Consume(state)
	require.True(t, ok)
	require.Equal(t, int64(42), pending.InternalUserID)
	require.Equal(t, "alice@example.com", pending.Email)
}

func TestKYCService_SingpassCallback_passesWhenNamePresent(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		info:  &proxy.UserInfo{Name: "USER S8979373D", Email: "alice@example.com"},
	}
	seedState(store, "st", 42, "alice@example.com")
	users.On("UpdateKYCStatus", mock.Anything, int64(42), model.KYCStatusPassed).Return(nil)

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.NoError(t, err)
	users.AssertExpectations(t)
}

func TestKYCService_SingpassCallback_failsKYCWhenNameEmpty(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		info:  &proxy.UserInfo{Name: "", Email: "alice@example.com"},
	}
	seedState(store, "st", 42, "alice@example.com")
	users.On("UpdateKYCStatus", mock.Anything, int64(42), model.KYCStatusFailed).Return(nil)

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.NoError(t, err)
	users.AssertExpectations(t)
}

func TestKYCService_SingpassCallback_rejectsInvalidState(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{token: "access-token"}

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "unknown")

	require.ErrorIs(t, err, ErrInvalidOAuthState)
	users.AssertNotCalled(t, "UpdateKYCStatus", mock.Anything, mock.Anything, mock.Anything)
}

func TestKYCService_SingpassCallback_rejectsEmailMismatch(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		info:  &proxy.UserInfo{Name: "USER", Email: "other@example.com"},
	}
	seedState(store, "st", 42, "alice@example.com")

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.ErrorIs(t, err, ErrKYCEmailMismatch)
	users.AssertNotCalled(t, "UpdateKYCStatus", mock.Anything, mock.Anything, mock.Anything)
}

func TestKYCService_SingpassCallback_allowsClerkTestEmailAlias(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		info:  &proxy.UserInfo{Name: "USER", Email: "alice@example.com"},
	}
	seedState(store, "st", 42, "alice+clerk_test@example.com")
	users.On("UpdateKYCStatus", mock.Anything, int64(42), model.KYCStatusPassed).Return(nil)

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.NoError(t, err)
	users.AssertExpectations(t)
}

func TestEmailsMatchForKYC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pendingEmail  string
		singpassEmail string
		want          bool
	}{
		{name: "exact match", pendingEmail: "alice@example.com", singpassEmail: "alice@example.com", want: true},
		{name: "case insensitive", pendingEmail: "Alice@Example.com", singpassEmail: "alice@example.com", want: true},
		{name: "clerk_test alias", pendingEmail: "alice+clerk_test@example.com", singpassEmail: "alice@example.com", want: true},
		{name: "clerk_test alias case", pendingEmail: "Alice+clerk_test@Example.com", singpassEmail: "alice@example.com", want: true},
		{name: "mismatch", pendingEmail: "alice@example.com", singpassEmail: "bob@example.com", want: false},
		{name: "clerk_test still mismatches other user", pendingEmail: "alice+clerk_test@example.com", singpassEmail: "bob@example.com", want: false},
		{name: "trim spaces", pendingEmail: "  alice@example.com  ", singpassEmail: "alice@example.com", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, emailsMatchForKYC(tt.pendingEmail, tt.singpassEmail))
		})
	}
}

func TestKYCService_SingpassCallback_propagatesTokenError(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{tokenErr: errors.New("token failed")}
	seedState(store, "st", 42, "alice@example.com")

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.Error(t, err)
}

func TestKYCService_SingpassCallback_propagatesUserInfoError(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{token: "access-token", infoErr: errors.New("userinfo failed")}
	seedState(store, "st", 42, "alice@example.com")

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.Error(t, err)
}

func TestKYCService_SingpassCallback_propagatesUpdateError(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		info:  &proxy.UserInfo{Name: "USER", Email: "alice@example.com"},
	}
	seedState(store, "st", 42, "alice@example.com")
	users.On("UpdateKYCStatus", mock.Anything, int64(42), model.KYCStatusPassed).
		Return(errors.New("update failed"))

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.Error(t, err)
}

func TestKYCService_SingpassCallback_consumesStateOnce(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		info:  &proxy.UserInfo{Name: "USER", Email: "alice@example.com"},
	}
	seedState(store, "st", 42, "alice@example.com")
	users.On("UpdateKYCStatus", mock.Anything, int64(42), model.KYCStatusPassed).Return(nil)

	svc := newKYCService(sp, users, store)
	require.NoError(t, svc.SingpassCallback(context.Background(), "auth-code", "st"))
	require.ErrorIs(t, svc.SingpassCallback(context.Background(), "auth-code", "st"), ErrInvalidOAuthState)
}

func TestKYCService_SingpassCallback_rejectsExpiredState(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	fixed := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }
	seedState(store, "st", 42, "alice@example.com")
	store.now = func() time.Time { return fixed.Add(2 * time.Minute) }

	svc := newKYCService(&fakeSingpassProxy{token: "access-token"}, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.ErrorIs(t, err, ErrInvalidOAuthState)
	users.AssertNotCalled(t, "UpdateKYCStatus", mock.Anything, mock.Anything, mock.Anything)
}

func TestKYCService_SingpassCallback_rejectsEmptyState(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	seedState(store, "st", 42, "alice@example.com")

	svc := newKYCService(&fakeSingpassProxy{token: "access-token"}, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "")

	require.ErrorIs(t, err, ErrInvalidOAuthState)
	users.AssertNotCalled(t, "UpdateKYCStatus", mock.Anything, mock.Anything, mock.Anything)
}

func TestKYCService_SingpassCallback_updatesBoundUserNotEmailLookup(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		// Singpass email matches a different account conceptually; KYC must follow state binding.
		info: &proxy.UserInfo{Name: "USER", Email: "alice@example.com"},
	}
	seedState(store, "st", 99, "alice@example.com")
	users.On("UpdateKYCStatus", mock.Anything, int64(99), model.KYCStatusPassed).Return(nil)

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.NoError(t, err)
	users.AssertExpectations(t)
}

func TestKYCService_SingpassCallback_allowsCaseInsensitiveEmailMatch(t *testing.T) {
	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		info:  &proxy.UserInfo{Name: "USER", Email: "Alice@Example.com"},
	}
	seedState(store, "st", 42, "alice@example.com")
	users.On("UpdateKYCStatus", mock.Anything, int64(42), model.KYCStatusPassed).Return(nil)

	svc := newKYCService(sp, users, store)
	err := svc.SingpassCallback(context.Background(), "auth-code", "st")

	require.NoError(t, err)
}

func TestKYCService_StartSingpassLogin_roundTripWithCallback(t *testing.T) {
	prev := config.Config.SingpassConfig
	config.Config.SingpassConfig = &config.SingpassConfig{
		RedirectURI: "http://localhost/callback",
		Scope:       "openid",
		IssuerURL:   "https://idp.example/singpass/v2",
	}
	t.Cleanup(func() { config.Config.SingpassConfig = prev })
	t.Setenv("SINGPASS_CLIENT_ID", "client-id")

	users := new(mocks.UserDao)
	store := newMemoryKYCStateStore(time.Minute)
	sp := &fakeSingpassProxy{
		token: "access-token",
		info:  &proxy.UserInfo{Name: "USER", Email: "alice@example.com"},
	}
	users.On("UpdateKYCStatus", mock.Anything, int64(42), model.KYCStatusPassed).Return(nil)

	svc := newKYCService(sp, users, store)
	authorizeURL, err := svc.StartSingpassLogin(context.Background(), 42, "alice@example.com")
	require.NoError(t, err)

	u, err := urlpkg.Parse(authorizeURL)
	require.NoError(t, err)
	state := u.Query().Get("state")
	require.NotEmpty(t, state)

	require.NoError(t, svc.SingpassCallback(context.Background(), "auth-code", state))
	require.ErrorIs(t, svc.SingpassCallback(context.Background(), "auth-code", state), ErrInvalidOAuthState)
	users.AssertExpectations(t)
}

var _ proxy.SingpassProxy = (*fakeSingpassProxy)(nil)
