package pkg

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	//"math/rand"
	"github.com/HaoAsakura123/medodsTest/internal/storage"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Manager struct {
	SecretKey string
}

type TokenManager interface {
	NewJWT(user storage.User, ttl time.Duration) (string, error)
	NewRefreshToken() (string, error)
	ValidateJWT(tokenString string) (jwt.MapClaims, error)
}

func (m *Manager) NewJWT(user storage.User, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(ttl)},
		Subject:   user.GUID,
	})
	return token.SignedString([]byte(m.SecretKey))
}

func (m *Manager) NewRefreshToken(guid string, expiry time.Duration) (string, error) {
	// tokenRaw := m.generateRandomToken()
	expiredAt := time.Now().Add(expiry).Unix()
	payload := fmt.Sprintf("%s:%d", guid, expiredAt)

	h := hmac.New(sha1.New, []byte(m.SecretKey))
	h.Write([]byte(payload))

	return base64.URLEncoding.EncodeToString([]byte(payload)), nil
}

// func (m *Manager) generateRandomToken() string {
// 	const abc = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789"
// 	s := make([]byte, 8)
// 	for i := range s {
// 		s[i] = abc[rand.Intn(len(abc))]
// 	}
// 	return string(s)
// }

func (m *Manager) ValidateRefreshToken(b64Token string) (string, error) { // проверка рефреш токена
	tokenBytes, err := base64.URLEncoding.DecodeString(b64Token)
	if err != nil {
		log.Printf("ERROR: invalid token")
		return "", err
	}
	signedToken := string(tokenBytes)

	parts := strings.Split(signedToken, ":")
	if len(parts) != 2 {
		log.Printf("ERROR: invalid token")
		return "", err
	}

	expiredAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		log.Printf("uncorrect exp time")
		return "", err
	}

	if time.Now().Unix() > expiredAt {
		log.Printf("token exp")
		return "", err
	}

	return parts[0], nil
}

func HashToken(pass string) (string, error) {
	//log.Println(len(pass))
	hashPass, err := bcrypt.GenerateFromPassword([]byte(pass), 14)
	if err != nil {
		return "", err
	}
	return string(hashPass), err
}

func UnhashToken(hash, pass string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
}

func (m *Manager) ValidateJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(m.SecretKey), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))
	if err != nil {
		log.Printf("Something go wrong with token %s:", err)
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}
