package middleware

import (
	"net/http"
	"strings"

	"github.com/HaoAsakura123/medodsTest/internal/pkg"
	"github.com/HaoAsakura123/medodsTest/internal/storage"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(jwtSecret string, repo *storage.UserRepository) gin.HandlerFunc {
	jwtManager := &pkg.Manager{
		SecretKey: jwtSecret,
	}

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Authorization header is required",
				"details": "Format: 'Bearer <token>'",
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid authorization header format",
				"details": "Expected format: 'Bearer <token>'",
			})
			return
		}

		token := parts[1]

		guid, err := jwtManager.ValidateJWT(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid token",
				"details": err.Error(),
			})
			return
		}

		isAuthorized, err := repo.IsUserAuthorized(guid)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error":   "Internal server error",
				"details": "Failed to check user authorization status",
			})
			return
		}

		if !isAuthorized {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"details": "User is not authorized or session was terminated",
			})
			return
		}

		c.Set("userGUID", guid)       // нужно потом это поле извлекать из контекста и сравнивать
		c.Set("secretKey", jwtSecret) // для проверки

		c.Next()
	}
}
