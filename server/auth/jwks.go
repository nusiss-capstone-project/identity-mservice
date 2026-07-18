package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
)

const jwksCacheTTL = 5 * time.Minute

var jwksHTTPClient = &http.Client{Timeout: 5 * time.Second}

type jwksCache struct {
	url       string
	expiresAt time.Time
	keys      map[string]*rsa.PublicKey
	mu        sync.Mutex
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{url: url, keys: map[string]*rsa.PublicKey{}}
}

func (c *jwksCache) publicKey(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if now.Before(c.expiresAt) {
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
		return nil, errors.New("clerk jwks key not found")
	}
	if err := c.refresh(); err != nil {
		return nil, err
	}
	key, ok := c.keys[kid]
	if !ok {
		return nil, errors.New("clerk jwks key not found")
	}
	return key, nil
}

func (c *jwksCache) refresh() error {
	resp, err := jwksHTTPClient.Get(c.url) // #nosec G107 -- configured Clerk JWKS URL.
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Logger.Errorw("failed to close clerk jwks response body", "error", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to fetch clerk jwks")
	}
	var body jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(body.Keys))
	for _, raw := range body.Keys {
		if raw.KTY != "RSA" || raw.N == "" || raw.E == "" || raw.KID == "" {
			continue
		}
		key, err := rsaPublicKey(raw.N, raw.E)
		if err != nil {
			continue
		}
		keys[raw.KID] = key
	}
	c.keys = keys
	c.expiresAt = time.Now().Add(jwksCacheTTL)
	return nil
}

func rsaPublicKey(nRaw, eRaw string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nRaw)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eRaw)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func verifyRS256(pub *rsa.PublicKey, signingInput string, signature []byte) error {
	digest := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature)
}
