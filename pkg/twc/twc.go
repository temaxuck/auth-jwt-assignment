// TWC - Token Web Container
package twc

// TODO: Allow contain custom payload
// TODO: Allow custom encoding/decoding algorithms
// TODO: Allow custom raw token generation algorithms
// TODO: Maybe fields could be private

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const TOKEN_HASH_SIZE = 36 // = $(Bcrypt Max Password Length) / $(Chars Per byte) = 72 / 2

type TokenWebContainer struct {
	TokenID  string
	RawToken string
}

func New(tokenID string) (*TokenWebContainer, error) {
	raw, err := generateRawToken()
	if err != nil {
		return nil, err
	}

	return &TokenWebContainer{
		TokenID:  tokenID,
		RawToken: raw,
	}, nil
}

func Decode(tokenB64 string) (c *TokenWebContainer, err error) {
	decodedToken, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 string")
	}

	tokenParts := strings.Split(string(decodedToken), ":")
	if len(tokenParts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	return &TokenWebContainer{
		TokenID:  tokenParts[0],
		RawToken: tokenParts[1],
	}, nil
}

// Return values:
//
//	token64   string - token to pass via web
//	tokenHash string - hashed token to store in the database
//	err       error
func (c *TokenWebContainer) Encode() (tokenB64 string, tokenHash string, err error) {
	tokenHash, err = hashToken(c.RawToken)
	if err != nil {
		return "", "", err
	}

	tokenString := fmt.Sprintf("%s:%s", c.TokenID, c.RawToken)
	return base64.StdEncoding.EncodeToString([]byte(tokenString)), tokenHash, nil
}

func (c *TokenWebContainer) Validate(tokenHash string) error {
	return bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(c.RawToken))
}

func hashToken(token string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(hash), err
}

func generateRawToken() (string, error) {
	bytes := make([]byte, TOKEN_HASH_SIZE)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), err
}
