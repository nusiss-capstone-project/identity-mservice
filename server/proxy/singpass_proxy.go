package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nusiss-capstone-project/identity-mservice/server/config"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
)

type UserInfo struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Address string `json:"address"`
	City    string `json:"city"`
	State   string `json:"state"`
	Zip     string `json:"zip"`
	Country string `json:"country"`
}

type SingpassProxy interface {
	GetAccessToken(ctx context.Context, code string) (string, error)
	GetUserInfo(ctx context.Context, token string) (*UserInfo, error)
}

type singpassProxyImpl struct {
	Client        *http.Client
	ClientID      string
	Issuer        string
	SigningKey    *singpassSigningKey
	EncryptionKey jwk.Key
	ASPKeySet     jwk.Set
}

var (
	singpassProxySyncOnce sync.Once
	singpassProxyInstance SingpassProxy
)

func GetSingpassProxy() SingpassProxy {
	singpassProxySyncOnce.Do(func() {
		singpassProxyInstance = newSingpassProxy()
	})
	return singpassProxyInstance
}

// BuildAuthorizeURL returns the Singpass v2 authorize URL. state and nonce must be unique per login attempt.
func BuildAuthorizeURL(state, nonce string) string {
	cfg := config.Config.SingpassConfig
	params := url.Values{
		"scope":         {cfg.Scope},
		"response_type": {"code"},
		"client_id":     {strings.TrimSpace(os.Getenv("SINGPASS_CLIENT_ID"))},
		"redirect_uri":  {cfg.RedirectURI},
		"state":         {state},
		"nonce":         {nonce},
	}
	return strings.TrimRight(cfg.IssuerURL, "/") + "/auth?" + params.Encode()
}

func newSingpassProxy() SingpassProxy {
	cfg := config.Config.SingpassConfig
	clientID := strings.TrimSpace(os.Getenv("SINGPASS_CLIENT_ID"))
	client := &http.Client{Timeout: 30 * time.Second}

	jwksURI := resolveJWKSURI(cfg.JWKSURI)
	var aspKeySet jwk.Set
	if jwksURI != "" {
		keySet, err := fetchJWKS(client, jwksURI)
		if err != nil {
			log.Logger.Errorw("singpass: failed to fetch jwks", "jwks_uri", jwksURI, "error", err)
		} else {
			aspKeySet = keySet
		}
	}

	signingKey, encryptionKey, err := loadClientKeys(client)
	if err != nil {
		log.Logger.Errorw("singpass: failed to load client keys", "error", err)
	}

	return &singpassProxyImpl{
		Client:        client,
		ClientID:      clientID,
		Issuer:        cfg.IssuerURL,
		SigningKey:    signingKey,
		EncryptionKey: encryptionKey,
		ASPKeySet:     aspKeySet,
	}
}

func resolveJWKSURI(configured string) string {
	if uri := strings.TrimSpace(os.Getenv("SINGPASS_JWKS_URI")); uri != "" {
		return uri
	}
	return strings.TrimSpace(configured)
}

func logHTTPError(msg string, resp *http.Response) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Logger.Errorw(msg, "status", resp.StatusCode, "read_body_error", err)
		return
	}
	log.Logger.Errorw(msg, "status", resp.StatusCode, "body", string(body))
}

func (p *singpassProxyImpl) GetAccessToken(ctx context.Context, code string) (string, error) {
	if p.SigningKey == nil {
		return "", errors.New("singpass signing key is not configured")
	}
	if p.ClientID == "" {
		return "", errors.New("singpass client id is not configured")
	}
	if p.Issuer == "" {
		return "", errors.New("singpass issuer url is not configured")
	}

	clientAssertion, err := p.SigningKey.clientAssertion(p.ClientID, p.Issuer)
	if err != nil {
		log.Logger.Errorw("singpass: failed to create client assertion", "error", err)
		return "", err
	}

	form := url.Values{
		"code":                  {code},
		"grant_type":            {"authorization_code"},
		"redirect_uri":          {config.Config.SingpassConfig.RedirectURI},
		"client_id":             {p.ClientID},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {clientAssertion},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Config.SingpassConfig.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Logger.Errorw("singpass: failed to create token request", "error", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Logger.Errorw("singpass: failed to get access token", "error", err)
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logHTTPError("singpass: failed to get access token", resp)
		return "", errors.New("failed to get access token")
	}

	var tokenResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResult); err != nil {
		log.Logger.Errorw("singpass: failed to decode token response", "error", err)
		return "", err
	}
	if tokenResult.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}
	return tokenResult.AccessToken, nil
}

func (p *singpassProxyImpl) GetUserInfo(ctx context.Context, token string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.Config.SingpassConfig.UserInfoURL, nil)
	if err != nil {
		log.Logger.Errorw("singpass: failed to create user info request", "error", err)
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/jwt, application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Logger.Errorw("singpass: failed to get user info", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Logger.Errorw("singpass: failed to read user info response", "error", err)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		log.Logger.Errorw("singpass: failed to get user info", "status", resp.StatusCode, "body", string(body))
		return nil, errors.New("failed to get user info")
	}

	userInfo, err := p.parseUserInfoResponse(body)
	if err != nil {
		log.Logger.Errorw("singpass: failed to parse user info response", "error", err)
		return nil, err
	}
	return userInfo, nil
}
