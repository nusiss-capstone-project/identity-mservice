package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// mockpassDefaultClientJWKS is the MockPass default RP private keyset
// (static/certs/oidc-v2-rp-secret.json). Used only when SINGPASS_CLIENT_JWKS /
// SINGPASS_CLIENT_JWKS_URI are unset, so local MockPass still works without a file.
const mockpassDefaultClientJWKS = `{
  "keys": [
    {
      "kty": "EC",
      "d": "AFOzlND2sq43ykty-VZXw-IEIOyHkBsNXUU77o5yEYcktpoMe9Dl3jsaXwzRK6wtDJH_uoz4IG1Uj4J_WyH5O3GS",
      "use": "sig",
      "crv": "P-521",
      "kid": "sig-2022-06-04T09:22:28Z",
      "x": "AAj_CAKL9NmP6agPCMto6_LiYQqko3o3ZWTtBg75bA__Z8yKEv_CwHzaibkVLnJ9XKWxCQeyEk9ROLhJoJuZxnsI",
      "y": "AZeoe0v-EwqD3oo1V5lxUAmC80qHt-ybqOsl1mYKPgE_ctGcD4hj8tVhmD0Of6ARuKVTxNWej-X82hEW_7Aa-XpR",
      "alg": "ES512"
    },
    {
      "kty": "EC",
      "d": "AP7xECOnlKW-FuLpe1h3ULZoqFzScFrbyAEQTFFG49j5HRHl0k13-6_6nWnwJ9Y8sTrGOWH4GszmDBBZGGvESJQr",
      "use": "enc",
      "crv": "P-521",
      "kid": "enc-2022-06-04T13:46:15Z",
      "x": "AB-16HyJwnlSZbQtqhFskADqFrm6rgX9XeaV8FgynX61750GCRbYjoueDosSNt-qzK5QNHskdQw0QZ700YF2JIlb",
      "y": "AZwYlSBSdV-CxGRMz6ovTvWxKJ6e44gaZHf-YfbJV7w9VdAJb3OuzbHNGRuzNDjEa8eH-paLDaAB84ezrEm1SRHq",
      "alg": "ECDH-ES+A256KW"
    }
  ]
}`

type singpassSigningKey struct {
	privateKey *ecdsa.PrivateKey
	kid        string
	method     jwt.SigningMethod
}

type jwksFile struct {
	Keys []jwkPrivateKey `json:"keys"`
}

type jwkPrivateKey struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	KID string `json:"kid"`
	Alg string `json:"alg"`
	D   string `json:"d"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// loadClientKeys loads RP private keys for client_assertion signing and userinfo decryption.
// Priority: SINGPASS_CLIENT_JWKS_URI > SINGPASS_CLIENT_JWKS > MockPass default keyset.
func loadClientKeys(client *http.Client) (*singpassSigningKey, jwk.Key, error) {
	raw, err := loadClientJWKSRaw(client)
	if err != nil {
		return nil, nil, err
	}

	var keyset jwksFile
	if err := json.Unmarshal(raw, &keyset); err != nil {
		return nil, nil, fmt.Errorf("parse client jwks: %w", err)
	}

	signingKey, err := parseSigningKey(keyset)
	if err != nil {
		return nil, nil, err
	}
	encryptionKey, err := parseEncryptionKey(keyset)
	if err != nil {
		return nil, nil, err
	}
	return signingKey, encryptionKey, nil
}

func loadClientJWKSRaw(client *http.Client) ([]byte, error) {
	if uri := strings.TrimSpace(os.Getenv("SINGPASS_CLIENT_JWKS_URI")); uri != "" {
		return fetchJWKSRaw(client, uri)
	}
	if raw := strings.TrimSpace(os.Getenv("SINGPASS_CLIENT_JWKS")); raw != "" {
		return []byte(raw), nil
	}
	return []byte(mockpassDefaultClientJWKS), nil
}

func parseSigningKey(keyset jwksFile) (*singpassSigningKey, error) {
	for _, key := range keyset.Keys {
		if key.Use != "sig" || key.KTY != "EC" || key.D == "" {
			continue
		}
		privateKey, method, err := jwkToECDSA(key)
		if err != nil {
			return nil, err
		}
		return &singpassSigningKey{
			privateKey: privateKey,
			kid:        key.KID,
			method:     method,
		}, nil
	}
	return nil, errors.New("no private signing key with use=sig found in client jwks")
}

func parseEncryptionKey(keyset jwksFile) (jwk.Key, error) {
	for _, key := range keyset.Keys {
		if key.Use != "enc" || key.D == "" {
			continue
		}
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		return jwk.ParseKey(keyJSON)
	}
	return nil, errors.New("no private encryption key with use=enc found in client jwks")
}

func jwkToECDSA(key jwkPrivateKey) (*ecdsa.PrivateKey, jwt.SigningMethod, error) {
	curve, method, err := curveAndMethod(key.Crv, key.Alg)
	if err != nil {
		return nil, nil, err
	}

	d, err := decodeBase64URLBigInt(key.D)
	if err != nil {
		return nil, nil, fmt.Errorf("decode d: %w", err)
	}
	x, err := decodeBase64URLBigInt(key.X)
	if err != nil {
		return nil, nil, fmt.Errorf("decode x: %w", err)
	}
	y, err := decodeBase64URLBigInt(key.Y)
	if err != nil {
		return nil, nil, fmt.Errorf("decode y: %w", err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, method, nil
}

func curveAndMethod(crv, alg string) (elliptic.Curve, jwt.SigningMethod, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), signingMethodForAlg(alg, jwt.SigningMethodES256), nil
	case "P-384":
		return elliptic.P384(), signingMethodForAlg(alg, jwt.SigningMethodES384), nil
	case "P-521":
		return elliptic.P521(), signingMethodForAlg(alg, jwt.SigningMethodES512), nil
	default:
		return nil, nil, fmt.Errorf("unsupported curve %q", crv)
	}
}

func signingMethodForAlg(alg string, fallback jwt.SigningMethod) jwt.SigningMethod {
	switch alg {
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	default:
		return fallback
	}
}

func decodeBase64URLBigInt(value string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func (k *singpassSigningKey) clientAssertion(clientID, issuer string) (string, error) {
	now := time.Now().Unix()
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(k.method, jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": issuer,
		"iat": now,
		"exp": now + 120,
		"jti": jti,
	})
	token.Header["typ"] = "JWT"
	token.Header["kid"] = k.kid
	return token.SignedString(k.privateKey)
}

func randomJTI() (string, error) {
	return RandomOAuthParam()
}

// RandomOAuthParam returns a cryptographically random OAuth state/nonce value.
func RandomOAuthParam() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
