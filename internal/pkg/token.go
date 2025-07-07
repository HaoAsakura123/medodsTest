package pkg

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"strconv"
	"strings"
	"time"

	"github.com/HaoAsakura123/medodsTest/internal/structure"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Manager struct {
	SecretKey string
}

type TokenManager interface {
	NewJWT(user structure.User, ttl time.Duration) (string, error)
	NewRefreshToken() (string, error)
	ValidateJWT(tokenString string) (string, error)
	ValidateRefreshToken(b64Token string) (string, error)
}

func (m *Manager) NewJWT(user structure.User, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(ttl)},
		Subject:   user.GUID,
	})
	return token.SignedString([]byte(m.SecretKey))
}

func (m *Manager) NewRefreshToken(guid string, expiry time.Duration) (string, error) {
	expiredAt := time.Now().Add(expiry).Unix()
	payload := fmt.Sprintf("%s:%d", guid, expiredAt)

	h := hmac.New(sha256.New, []byte(m.SecretKey))
	h.Write([]byte(payload))
	signature := h.Sum(nil)

	// Формируем токен без дополнительного кодирования
	token := fmt.Sprintf("%s.%s",
		base64.URLEncoding.EncodeToString([]byte(payload)),
		base64.URLEncoding.EncodeToString(signature))

	return token, nil
}

func (m *Manager) ValidateRefreshToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid refresh token format")
	}

	payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid payload encoding: %v", err)
	}
	payload := string(payloadBytes)

	receivedSig, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding: %v", err)
	}

	h := hmac.New(sha256.New, []byte(m.SecretKey))
	h.Write([]byte(payload))
	expectedSig := h.Sum(nil)

	if !hmac.Equal(receivedSig, expectedSig) {
		return "", fmt.Errorf("invalid refresh token signature")
	}

	payloadParts := strings.Split(payload, ":")
	if len(payloadParts) != 2 {
		return "", fmt.Errorf("invalid payload format")
	}

	guid := payloadParts[0]
	expiredAt, err := strconv.ParseInt(payloadParts[1], 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid expiration time")
	}

	if time.Now().Unix() > expiredAt {
		return "", fmt.Errorf("token refresh expired")
	}

	return guid, nil
}
func HashToken(token string) (string, error) {
	shaHash := sha256.Sum256([]byte(token))

	hash, err := bcrypt.GenerateFromPassword(shaHash[:], 14)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func UnhashToken(hash, token string) error {
	shaHash := sha256.Sum256([]byte(token))
	return bcrypt.CompareHashAndPassword([]byte(hash), shaHash[:])
}

func (m *Manager) ValidateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.SecretKey), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))

	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", fmt.Errorf("missing sub claim")
	}

	return sub, nil
}
