package pkg

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"

	//"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/HaoAsakura123/medodsTest/internal/storage"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Manager struct {
	SecretKey string
}

type TokenManager interface {
	NewJWT(user storage.User, ttl time.Duration) (string, error)
	NewRefreshToken() (string, error)
	ValidateJWT(tokenString string) (string, error)
	ValidateRefreshToken(b64Token string) (string, error) 
}

func (m *Manager) NewJWT(user storage.User, ttl time.Duration) (string, error) {
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
    
    token := fmt.Sprintf("%s.%s", payload, base64.URLEncoding.EncodeToString(signature))
    
    return base64.URLEncoding.EncodeToString([]byte(token)), nil
}

func (m *Manager) ValidateRefreshToken(b64Token string) (string, error) {

    tokenBytes, err := base64.URLEncoding.DecodeString(b64Token)
    if err != nil {
		log.Printf("invalid token encoding")
        return "", fmt.Errorf("invalid token encoding")
    }
    
    parts := strings.Split(string(tokenBytes), ".")
    if len(parts) != 2 {
		log.Printf("invalid token format")
        return "", fmt.Errorf("invalid token format")
    }
    
    payload := parts[0]
    receivedSig, err := base64.URLEncoding.DecodeString(parts[1])
    if err != nil {
		log.Printf("invalid signature format")
        return "", fmt.Errorf("invalid signature format")
    }
    
    h := hmac.New(sha256.New, []byte(m.SecretKey))
    h.Write([]byte(payload))
    expectedSig := h.Sum(nil)
    
    if !hmac.Equal(receivedSig, expectedSig) {
		log.Printf("invalid token signature")
        return "", fmt.Errorf("invalid token signature")
    }
    
    payloadParts := strings.Split(payload, ":")
    if len(payloadParts) != 2 {
		log.Printf("invalid payload format")
        return "", fmt.Errorf("invalid payload format")
    }
    
    guid := payloadParts[0]
    expiredAt, err := strconv.ParseInt(payloadParts[1], 10, 64)
    if err != nil {
		log.Printf("invalid expiration time")
        return "", fmt.Errorf("invalid expiration time")
    }
    
    if time.Now().Unix() > expiredAt {
		log.Printf("token expired")
        return "", fmt.Errorf("token expired")
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
    token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
    if err != nil {
		log.Printf("invalid token format: %v", err)
        return "", fmt.Errorf("invalid token format: %v", err)
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
		log.Printf("invalid token claims")
        return "", fmt.Errorf("invalid token claims")
    }

    sub, ok := claims["sub"].(string)
    if !ok || sub == "" {
        return "", fmt.Errorf("missing or invalid sub claim")
    }

    validToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte(m.SecretKey), nil
    }, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))

    if validToken != nil && validToken.Valid {
        return sub, nil
    }
    return sub, fmt.Errorf("invalid token: %v", err)
}
