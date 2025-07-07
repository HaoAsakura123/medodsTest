package app

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/HaoAsakura123/medodsTest/internal/middleware"
	"github.com/HaoAsakura123/medodsTest/internal/pkg"
	"github.com/HaoAsakura123/medodsTest/internal/storage"
	"github.com/HaoAsakura123/medodsTest/internal/structure"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	_ "github.com/HaoAsakura123/medodsTest/docs"
	"github.com/swaggo/files"       // swagger embed files
	"github.com/swaggo/gin-swagger" // gin-swagger middleware
)

func InitRouter() {
	repo, err := storage.InitDB()
	if err != nil {
		log.Fatalf("Cannot initialize database: %v", err)
	}
	defer repo.Close()

	r := gin.Default()

	r.POST("/register", func(c *gin.Context) {
		RegisterHandler(c, repo)
	})
	r.POST("/login", func(c *gin.Context) {
		LoginHandler(c, repo)
	})
	authMiddleware := middleware.AuthMiddleware(os.Getenv("JWTSecretKey"), repo)

	protected := r.Group("/")

	protected.Use(authMiddleware)
	{
		// нужно создать на сайте вебхук вручную, текущий https://webhook.site/60865246-f4ff-430a-a960-674ba190e91c
		protected.POST("/refresh", func(c *gin.Context) {
			RefreshHandler(c, repo, "https://webhook.site/60865246-f4ff-430a-a960-674ba190e91c")
		})

		protected.GET("/logout", func(c *gin.Context) {
			LogOutHandler(c, repo)
		})

		protected.GET("/about", func(c *gin.Context) {
			InfoAboutHandler(c, repo)
		})
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.Run(":8080")
}

// @Summary Login user
// @Description Login by UUID and receive JWT tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body structure.User true "User UUID"
// @Success 201 {object} map[string]string "Tokens successfully created"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 404 {object} map[string]string "User not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /login [post]
func LoginHandler(c *gin.Context, repo *storage.UserRepository) {
	user := structure.User{}

	if err := c.ShouldBindJSON(&user); err != nil {
		log.Printf("Validation error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	exists, err := repo.UserExists(user.GUID)
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	if !exists {
		log.Printf("User not found: %s", user.GUID)
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	secret := os.Getenv("JWTSecretKey")
	m := pkg.Manager{SecretKey: secret}

	newAccessToken, err := m.NewJWT(user, 25*time.Minute)
	if err != nil {
		log.Printf("Token creation error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token creation failed"})
		return
	}

	newRefreshToken, err := m.NewRefreshToken(user.GUID, time.Hour)
	if err != nil {
		log.Printf("Refresh token error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh token failed"})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	clientIP := c.ClientIP()
	if clientIP == "" {
		clientIP = "unknown"
	}

	if err := repo.SaveRefreshToken(user.GUID, newRefreshToken, userAgent, clientIP); err != nil {
		log.Printf("DB save error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session creation failed"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"access":  newAccessToken,
		"refresh": newRefreshToken,
		"uuid":    user.GUID,
	})
}

type email struct {
	Email string `json:"email" binding:"required"`
}

// @Summary Register a new user
// @Description Register user by email and receive UUID
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body email true "User email"
// @Success 200 {object} map[string]string "User successfully registered"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 409 {object} map[string]string "User already exists"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /register [post]
func RegisterHandler(c *gin.Context, repo *storage.UserRepository) {
	req := email{}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Validation error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	exists, err := repo.EmailExists(req.Email)
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	if exists {
		log.Printf("User already exists: %s", req.Email)
		c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
		return
	}

	guid := uuid.New().String()
	if err := repo.CreateUser(req.Email, guid); err != nil {
		log.Printf("Cannot create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user creation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "user created",
		"uuid":   guid,
	})
}

type authUsers struct {
	RefreshToken string `json:"refresh" binding:"required"`
}

// @Summary Refresh tokens
// @Description Refresh access and refresh tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body authUsers true "Refresh token"
// @Success 200 {object} map[string]string "Tokens successfully refreshed"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /refresh [post]
func RefreshHandler(c *gin.Context, repo *storage.UserRepository, webhookURL string) {
	tokens := authUsers{}
	guidAccess := c.MustGet("userGUID").(string)

	if err := c.ShouldBindJSON(&tokens); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	secret := c.MustGet("secretKey").(string)
	m := pkg.Manager{SecretKey: secret}

	guidRefresh, err := m.ValidateRefreshToken(tokens.RefreshToken)
	if err != nil {
		repo.DeleteAuth(guidAccess)
		log.Printf("invalid token: token signature is invalid")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if guidAccess != guidRefresh {
		repo.DeleteAuth(guidAccess)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token mismatch"})
		return
	}

	hash, err := repo.GetRefreshToken(guidAccess)
	if err != nil {
		repo.DeleteAuth(guidAccess)
		log.Printf("syh gone wrong while getting hash")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if err := pkg.UnhashToken(hash, tokens.RefreshToken); err != nil {
		repo.DeleteAuth(guidAccess)
		log.Printf("has diff hash")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "has diferent hash"})
		return
	}

	currentUserAgent := c.GetHeader("User-Agent")
	storedUserAgent, err := repo.GetUserAgent(guidAccess)
	if err != nil {
		repo.DeleteAuth(guidAccess)
		log.Printf("invalid token: token signature is invalid")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	if currentUserAgent != storedUserAgent {
		repo.DeleteAuth(guidAccess)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "session terminated due to User-Agent change",
		})
		return
	}

	currentIP := c.ClientIP()
	storedIP, err := repo.GetLastIP(guidAccess)

	if err != nil {
		log.Printf("Failed to get last IP: %v", err)
	}

	if currentIP != storedIP {
		log.Printf("IP changed, previous was %s, now %s", storedIP, currentIP)
		go func() {
			payload := map[string]interface{}{
				"event":      "login_from_new_ip",
				"user_guid":  guidAccess,
				"timestamp":  time.Now().UTC(),
				"old_ip":     storedIP,
				"new_ip":     currentIP,
				"user_agent": currentUserAgent,
			}
			jsonData, _ := json.Marshal(payload)
			_, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				log.Printf("Failed to send webhook: %v", err)
			}
			log.Printf("message was send to webhook")
		}()
	}

	if err := repo.UpdateLastIP(guidAccess, currentIP); err != nil {
		log.Printf("Failed to update IP: %v", err)
	}

	newAccessToken, err := m.NewJWT(structure.User{GUID: guidAccess}, 25*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}

	newRefreshToken, err := m.NewRefreshToken(guidAccess, time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create refresh token"})
		return
	}

	if err := repo.UpdateRefreshToken(guidAccess, newRefreshToken, currentUserAgent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken,
		"uuid":         guidAccess,
	})
}

// @Summary Logout user
// @Description Invalidate user's session
// @Tags Auth
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]string "Successfully logged out"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /logout [get]
func LogOutHandler(c *gin.Context, repo *storage.UserRepository) {

	guidAccess := c.MustGet("userGUID").(string)

	if err := repo.DeleteAuth(guidAccess); err != nil {
		log.Printf("Logout error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"uuid":   guidAccess,
	})
}

// @Summary Get user info
// @Description Get information about authenticated user
// @Tags Auth
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]string "User information"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "User not found"
// @Router /about [get]
func InfoAboutHandler(c *gin.Context, repo *storage.UserRepository) {

	guidAccess := c.MustGet("userGUID").(string)

	user, err := repo.GetUserByGUID(guidAccess)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"email": user.Email,
		"uuid":  user.GUID,
	})
}
