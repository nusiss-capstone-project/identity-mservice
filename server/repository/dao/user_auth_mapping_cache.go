package dao

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/model"
	cacheredis "github.com/nusiss-capstone-project/identity-mservice/server/repository/redis"
)

const (
	userAuthMappingCachePrefix = "user_auth_mapping:clerk:"
	userAuthMappingCacheTTL    = time.Hour
)

func userAuthMappingCacheKey(clerkUserID string) string {
	return userAuthMappingCachePrefix + clerkUserID
}

func (dao *UserAuthMappingDaoImpl) getMappingFromCache(ctx context.Context, clerkUserID string) (*model.UserAuthMapping, bool) {
	if !cacheredis.Available() || clerkUserID == "" {
		return nil, false
	}
	raw, err := cacheredis.Client.Get(ctx, userAuthMappingCacheKey(clerkUserID)).Bytes()
	if err != nil {
		return nil, false
	}
	var row model.UserAuthMapping
	if err := json.Unmarshal(raw, &row); err != nil {
		log.Logger.Warnw("invalid user auth mapping cache entry", "clerkUserID", clerkUserID, "error", err)
		_ = cacheredis.Client.Del(ctx, userAuthMappingCacheKey(clerkUserID)).Err()
		return nil, false
	}
	return &row, true
}

func (dao *UserAuthMappingDaoImpl) setMappingCache(ctx context.Context, row *model.UserAuthMapping) {
	if !cacheredis.Available() || row == nil || row.ClerkUserID == "" {
		return
	}
	raw, err := json.Marshal(row)
	if err != nil {
		log.Logger.Warnw("failed to marshal user auth mapping for cache", "error", err)
		return
	}
	if err := cacheredis.Client.Set(ctx, userAuthMappingCacheKey(row.ClerkUserID), raw, userAuthMappingCacheTTL).Err(); err != nil {
		log.Logger.Warnw("failed to set user auth mapping cache", "clerkUserID", row.ClerkUserID, "error", err)
	}
}

func (dao *UserAuthMappingDaoImpl) deleteMappingCache(ctx context.Context, clerkUserID string) {
	if !cacheredis.Available() || clerkUserID == "" {
		return
	}
	if err := cacheredis.Client.Del(ctx, userAuthMappingCacheKey(clerkUserID)).Err(); err != nil {
		log.Logger.Warnw("failed to delete user auth mapping cache", "clerkUserID", clerkUserID, "error", err)
	}
}
