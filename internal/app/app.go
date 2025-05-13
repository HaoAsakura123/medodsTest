package app

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/HaoAsakura123/medodsTest/internal/pkg"
	"github.com/HaoAsakura123/medodsTest/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	_ "github.com/HaoAsakura123/medodsTest/docs"
	"github.com/swaggo/files"       // swagger embed files
	"github.com/swaggo/gin-swagger" // gin-swagger middleware
)



func InitRouter(){
	var db *storage.Database
	db, err := storage.InitBD()

	if err != nil {
		log.Fatal("Cannot initianilise db")
	}
	defer db.CloseDB()
	r := gin.Default()

	r.Use(DatabaseMiddleware(db))

	r.POST("/register", RegisterHandler)
	r.POST("/login", LoginHandler)
	r.POST("/refresh", RefreshHandler)
	// authGroup := r.Group("/auth")
	// authGroup.Use(AuthMiddleware())
	// {
	// 	authGroup.GET("/about", InfoAboutHandler)
	// }
	r.GET("/about", InfoAboutHandler)
	r.DELETE("/logout", LogOutHandler) 
	
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.Run(":8080")
}



func DatabaseMiddleware(db *storage.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		pass := os.Getenv("POSTGRES_PASSWORD")
		c.Set(pass, db)
		c.Next()
	}
}

// @Summary LoginHandler
// @Description Login by UUID and receive JWT and refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Param GUID body storage.User true "User UUID"
// @Success 201 {object} map[string]string
// @Router /login [post]
func LoginHandler(c *gin.Context) {
	// генерация jwt refresh token по uuid
	user := storage.User{}

	if err := c.ShouldBindJSON(&user); err != nil {
		log.Printf("ERROR: Validation error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pass := os.Getenv("POSTGRES_PASSWORD")
	value, exists := c.Get(pass)
	if !exists {
		log.Printf("ERROR: should be a pass for db:")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		return
	}
	db := value.(*storage.Database)
	query := `SELECT id FROM users WHERE uuid = $1`
	row := db.BD.QueryRow(query, user.GUID)

	var userID int
	err := row.Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found: %s", user.GUID)
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		} else {
			log.Printf("Database error for user %s: %v", user.GUID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return
	}

	secret := os.Getenv("JWTSecretKey")
	m := pkg.Manager{SecretKey: secret}

	newAccessToken, err := m.NewJWT(user, 25*time.Minute)
	if err != nil {
		log.Printf("ERROR: cannot create access token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		return
	}
	newRefreshToken, err := m.NewRefreshToken(user.GUID, time.Duration(time.Hour))
	if err != nil {
		log.Printf("ERROR: cannot create refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		return
	}
	hashPass, err := pkg.HashToken(newRefreshToken)
	if err != nil {
		log.Printf("ERROR: cannot create hash from refresh")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		return
	}

	var id int
	userAgent := c.GetHeader("User-Agent")
	insertQuery := `INSERT INTO auth_users (uuid, password_hash, expired_at, user_agent) VALUES ($1, $2, NOW() + INTERVAL '31 day', $3) RETURNING id`
	err = db.BD.QueryRow(insertQuery, user.GUID, hashPass, userAgent).Scan(&id)
	if err != nil {
		log.Printf("ERROR: user already login %v:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user already login"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"authorisation":  newAccessToken,
		"refresh": newRefreshToken,
		"uuid": user.GUID,
	})

}
type Email struct{
	Email string `json:"email" binding:"required"`
}

// @Summary      Register a new user
// @Description  Register a user by email and receive a UUID
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param EMAIL body Email true "User EMAIL"
// @Success      200   {object}  map[string]string  "User successfully registered"
// @Failure      400   {object}  map[string]string  "Validation error"
// @Failure      500   {object}  map[string]string  "Internal server error"
// @Router       /register [post]
func RegisterHandler(c *gin.Context) {
	pass := os.Getenv("POSTGRES_PASSWORD")
	value, exists := c.Get(pass)
	if !exists {
		log.Printf("ERROR: database is not exists")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database isnt exists"})
		return
	}
	db := value.(*storage.Database)
	var user struct {
		Email string `json:"email" binding:"required"`
	}
	if err := c.ShouldBindJSON(&user); err != nil {
		log.Printf("ERROR: Validation error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `SELECT id FROM users WHERE email = $1`
	row := db.BD.QueryRow(query, user.Email)
	err := row.Scan(&user)
	var id int
	guid := ""
	if err == sql.ErrNoRows {
		guid = uuid.New().String()
		insertQuery := `INSERT INTO users (email, uuid) VALUES ($1, $2) RETURNING id`
		err = db.BD.QueryRow(insertQuery, user.Email, guid).Scan(&id)
		if err != nil {
			log.Printf("ERROR: cannot insert user into tables users")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot insert user into tables users"})
			return
		}
	} else {
		log.Printf("INFO: User already exists in table users")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User already exists in table users"})
		return
	}
	log.Printf("INFO: user was add to table users")
	c.JSON(http.StatusOK, gin.H{
		"status": "user was add to table",
		"GUID":   guid,
	})
}

type Auth_User struct {
	JWTtoken     string `json:"authorisation" binding:"required"`
	RefreshToken string `json:"refresh" binding:"required"`
	GUID string `json:"uuid"`
}



// @Summary      Refresh JWT and refresh token
// @Description  Refresh JWT and refresh token using the previous refresh token
// @Tags         Auth
// @Produce      json
// @Param Tokens body storage.Tokens true "Tokens"
// @Success      202  {object}  map[string]string  "Tokens successfully refreshed"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Router       /refresh [post]
func RefreshHandler(c *gin.Context) {
	tokens := storage.Tokens{}

    if err := c.ShouldBindJSON(&tokens); err != nil {
		log.Printf("Bad request %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    pass := os.Getenv("POSTGRES_PASSWORD")
    value, exists := c.Get(pass)
    if !exists {
		log.Printf("database error")
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
        return
    }

    db := value.(*storage.Database)
    
    query := `SELECT password_hash FROM auth_users WHERE uuid = $1`
    row := db.BD.QueryRow(query, tokens.GUID)

    var hashPass string
    if err := row.Scan(&hashPass); err != nil {
        if err == sql.ErrNoRows {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
        } else {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
        }
        return
    }

    if err := pkg.UnhashToken(hashPass, tokens.RefreshToken); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
        return
    }
    secret := os.Getenv("JWTSecretKey")
    m := pkg.Manager{SecretKey: secret}

	//guid from refresh != guid from jwt
	guidRefresh, err := m.ValidateRefreshToken(tokens.RefreshToken)
	if err != nil{
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
        return
	}
	guidAccess, err := m.ValidateJWT(tokens.AccessToken)
	if err != nil{
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
        return
	}
	if guidAccess != guidRefresh && guidAccess != tokens.GUID{
		log.Printf("someone changed tokens")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh or access token"})
        return
	}

	//

    newAccessToken, err := m.NewJWT(storage.User{GUID: tokens.GUID}, 25*time.Minute)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
        return
    }

    newRefreshToken, err := m.NewRefreshToken(tokens.GUID, time.Hour)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create refresh token"})
        return
    }

    newHashPass, err := pkg.HashToken(newRefreshToken)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash token"})
        return
    }

    _, err = db.BD.Exec(`UPDATE auth_users SET password_hash = $1 WHERE uuid = $2`, newHashPass, tokens.GUID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "authorisation": newAccessToken,
        "refresh":      newRefreshToken,
    })
}

type GUIDstr struct{
	GUID string `json:"uuid" binding:"required"`
}

// @Summary      Log out user
// @Description  Delete user's authentication data from the database
// @Tags         Auth
// @Produce      json
// @Param GUID body GUIDstr true "User UUID"
// @Success      200  {object}  map[string]string  "Successfully logged out"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Router       /logout [delete]
func LogOutHandler(c *gin.Context) {
    var req struct {
        GUID string `json:"uuid" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Bad request %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    pass := os.Getenv("POSTGRES_PASSWORD")
    dbValue, exists := c.Get(pass)
    if !exists {
		log.Printf("errors with database")
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
        return
    }

    db := dbValue.(*storage.Database)
    storage.DeleteAuth(db, req.GUID)
    
    c.JSON(http.StatusOK, gin.H{
        "status": "success",
        "GUID":   req.GUID,
    })
}


// @Summary      Get information about authorized user
// @Description  Retrieve information about the currently authorized user
// @Tags         Auth
// @Produce      json
// @Success      200  {object}  map[string]string  "Successfully retrieved user information"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Router       /about [get]
// @Security     ApiKeyAuth
func InfoAboutHandler(c *gin.Context) {

	// Здесь оказывается вообще все неправильно
	// Очень хочется переделать, но увы не успею,
	//Концептуально нужно брать JWT token и его валидировать из хеадера авторизации
	// так как у гет запроса не должно быть полей body
	// я конечно попробую успеть - но это не факт
	// вроде подправил
    authHeader := c.GetHeader("Authorization")
    if authHeader == "" {
		log.Printf("Authorization header is required!")
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
        return
    }
	parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        log.Printf("invalid authorization header format")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
        return
    }
	secret := os.Getenv("JWTSecretKey")
    m := pkg.Manager{SecretKey: secret}
	guid, err := m.ValidateJWT(parts[1])
	if err != nil{
		log.Printf("invalid jwt token")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized user"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"status":  "access",
		"GUID":    guid,
	})
}

