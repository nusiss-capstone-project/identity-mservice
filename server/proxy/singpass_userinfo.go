package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/nusiss-capstone-project/identity-mservice/server/config"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
)

func fetchJWKS(client *http.Client, jwksURI string) (jwk.Set, error) {
	body, err := fetchJWKSRaw(client, jwksURI)
	if err != nil {
		return nil, err
	}
	return jwk.Parse(body)
}

func fetchJWKSRaw(client *http.Client, jwksURI string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Logger.Errorw("singpass: failed to close jwks response body", "error", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: status %d body=%s", resp.StatusCode, string(body))
	}
	return body, nil
}

func (p *singpassProxyImpl) parseUserInfoResponse(body []byte) (*UserInfo, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, fmt.Errorf("empty userinfo response")
	}

	if strings.HasPrefix(trimmed, "{") {
		var userInfo UserInfo
		if err := json.Unmarshal(body, &userInfo); err != nil {
			return nil, fmt.Errorf("parse plain userinfo json: %w", err)
		}
		return &userInfo, nil
	}

	return p.decryptUserInfo(trimmed)
}

func (p *singpassProxyImpl) decryptUserInfo(encrypted string) (*UserInfo, error) {
	if p.EncryptionKey == nil {
		return nil, fmt.Errorf("singpass encryption key is not configured")
	}
	if p.ASPKeySet == nil {
		return nil, fmt.Errorf("singpass jwks is not configured")
	}

	decryptionKeySet := jwk.NewSet()
	if err := decryptionKeySet.AddKey(p.EncryptionKey); err != nil {
		return nil, fmt.Errorf("build decryption key set: %w", err)
	}

	decrypted, err := jwe.Decrypt(
		[]byte(encrypted),
		jwe.WithKeySet(decryptionKeySet),
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt userinfo jwe: %w", err)
	}

	verified, err := jws.Verify(decrypted, jws.WithKeySet(p.ASPKeySet))
	if err != nil {
		return nil, fmt.Errorf("verify userinfo jws: %w", err)
	}

	userInfo := mapSingpassClaimsToUserInfo(verified)
	if userInfo.Name == "" && userInfo.Email == "" && userInfo.Phone == "" {
		log.Logger.Warnw(
			"singpass: userinfo claims are empty; authorize scope at login time did not include name/email/mobileno (config scope only applies to /web/kyc/singpass/login)",
			"configured_scope", config.Config.SingpassConfig.Scope,
			"userInfo", userInfo.String(),
		)
	} else {
		log.Logger.Debugw("singpass: parsed userinfo claims", "userInfo", userInfo.String())
	}

	return userInfo, nil
}

func mapSingpassClaimsToUserInfo(verified []byte) *UserInfo {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(verified, &claims); err != nil {
		return &UserInfo{}
	}

	return &UserInfo{
		Name:    extractSingpassClaim(claims, "name"),
		Email:   extractSingpassClaim(claims, "email"),
		Phone:   extractSingpassClaim(claims, "mobileno"),
		Address: extractSingpassClaim(claims, "regadd"),
	}
}

func extractSingpassClaim(claims map[string]json.RawMessage, key string) string {
	return parseSingpassClaimValue(claims[key])
}

func parseSingpassClaimValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var wrapped struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && wrapped.Value != "" {
		return wrapped.Value
	}

	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain
	}

	return ""
}
