package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/repository/dao"
)

var errInvalidToken = errors.New("invalid clerk token")

type jwtHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
}

type jwtClaims struct {
	Subject   string  `json:"sub"`
	Issuer    string  `json:"iss"`
	Email     string  `json:"email"`
	Expiry    float64 `json:"exp"`
	NotBefore float64 `json:"nbf"`
}

// Authenticator verifies Clerk JWTs and maps them to internal users.
type Authenticator struct {
	issuer  string
	jwks    *jwksCache
	mapping dao.UserAuthMappingDao
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{
		issuer:  strings.TrimSpace(os.Getenv("CLERK_ISSUER")),
		jwks:    newJWKSCache(strings.TrimSpace(os.Getenv("CLERK_JWKS_URL"))),
		mapping: dao.GetUserAuthMappingDao(),
	}
}

func (a *Authenticator) Authenticate(ctx context.Context, token string) (*User, error) {
	claims, err := a.verifyToken(token)
	if err != nil {
		return nil, err
	}
	mapping, err := a.mapping.GetByClerkUserID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	if mapping == nil {
		return nil, errInvalidToken
	}
	email := claims.Email
	if email == "" {
		email = mapping.Email
	}
	return &User{
		InternalUserID: mapping.InternalUserID,
		ClerkUserID:    mapping.ClerkUserID,
		Email:          email,
		Role:           mapping.Role,
	}, nil
}

func (a *Authenticator) verifyToken(token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || a.jwks.url == "" {
		return nil, errInvalidToken
	}
	var header jwtHeader
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return nil, errInvalidToken
	}
	if header.Alg != "RS256" || header.KID == "" {
		return nil, errInvalidToken
	}
	var claims jwtClaims
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return nil, errInvalidToken
	}
	if err := a.validateClaims(&claims); err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errInvalidToken
	}
	pub, err := a.jwks.publicKey(header.KID)
	if err != nil {
		return nil, errInvalidToken
	}
	if err := verifyRS256(pub, parts[0]+"."+parts[1], signature); err != nil {
		return nil, errInvalidToken
	}
	return &claims, nil
}

func (a *Authenticator) validateClaims(claims *jwtClaims) error {
	now := time.Now()
	if claims.Subject == "" {
		return errInvalidToken
	}
	if a.issuer != "" && claims.Issuer != a.issuer {
		return errInvalidToken
	}
	if claims.Expiry == 0 || now.After(time.Unix(int64(claims.Expiry), 0)) {
		return errInvalidToken
	}
	if claims.NotBefore > 0 && now.Before(time.Unix(int64(claims.NotBefore), 0)) {
		return errInvalidToken
	}
	return nil
}

func decodeJWTPart(raw string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func devBypassEnabled() bool {
	return os.Getenv("APP_ENV") == "local" && strings.EqualFold(os.Getenv("AUTH_DEV_BYPASS"), "true")
}

func devBypassAllowed(clientIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	return ip != nil && ip.IsLoopback()
}

func devBypassAllowedRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = remoteAddr
	}
	return devBypassAllowed(host)
}

func devBypassUser() *User {
	// Localhost-only demo bypass. Never enable AUTH_DEV_BYPASS on network-accessible instances.
	return &User{InternalUserID: 1, ClerkUserID: "dev_bypass", Email: "demo@example.com", Role: RoleAdmin}
}
