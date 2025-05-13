package app

import (
	"database/sql"
	"log"
	"net/http"
	"os"
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
	authGroup := r.Group("/auth")
	authGroup.Use(AuthMiddleware())
	{
		authGroup.GET("/about", InfoAboutHandler)
		authGroup.POST("/refresh", RefreshHandler)
		authGroup.DELETE("/logout", LogOutHandler) 
	}
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

// @Summary      Register a new user
// @Description  Register a user by email and receive a UUID
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param GUID body storage.User true "User UUID"
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

// @Summary      Authorization Middleware
// @Description  Middleware to validate JWT token and refresh token
// @Tags         Middleware
// @Security     ApiKeyAuth
// @Param        Authorization  header    string  true  "JWT Token"
// @Failure      401            {object}  map[string]string  "Unauthorized"
// @Failure      500            {object}  map[string]string  "Internal Server Error"
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := Auth_User{}
		if err := c.ShouldBindJSON(&user); err != nil {
			log.Printf("ERROR: Validation error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			c.Abort()
		}
		c.Set("refresh", user.RefreshToken)
		secret := os.Getenv("JWTSecretKey")
		m := pkg.Manager{SecretKey: secret}
		pass := os.Getenv("POSTGRES_PASSWORD")
		value, exists := c.Get(pass)
		if !exists {
			log.Printf("ERROR: should be a pass for db:")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
			c.Abort()
		}
		db := value.(*storage.Database)
		// проверить jwt вообще актуален ли? +
		// проверка есть ли refresh токен в бд

		claims, err := m.ValidateJWT(user.JWTtoken)
		if err != nil {
			log.Printf("ERROR: Uncorrect authorisation: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			if user.GUID != ""{
				storage.DeleteAuth(db, user.GUID)
			}
			c.Abort()
		}
		sub, ok := claims["sub"]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing sub claim"})
			return
		}
		
		GUID, ok := sub.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid sub claim type"})
			return
		}
		c.Set("guid", GUID)
		query := `SELECT password_hash FROM auth_users WHERE uuid = $1`
		row := db.BD.QueryRow(query, GUID)

		var hashPass string
		err = row.Scan(&hashPass)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("User not found: %s", GUID)
				c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			} else {
				log.Printf("Database error for user %s: %v", GUID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
			}
			storage.DeleteAuth(db, user.GUID)
			c.Abort()
		}
		//
		err = pkg.UnhashToken(hashPass, user.RefreshToken)
		if err != nil {
			log.Printf("ERROR: invalid refresh token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
			storage.DeleteAuth(db, user.GUID)
			c.Abort()
		}


		c.Next()

		//нужно 
	}
}

// @Summary      Get information about authorized user
// @Description  Retrieve information about the currently authorized user
// @Tags         Auth
// @Produce      json
// @Param GUID body storage.User true "User UUID"
// @Success      200  {object}  map[string]string  "Successfully retrieved user information"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Router       /auth/about [get]
// @Security     ApiKeyAuth
func InfoAboutHandler(c *gin.Context) {

	// Здесь оказывается вообще все неправильно
	// Очень хочется переделать, но увы не успею,
	//Концептуально нужно брать JWT token и его валидировать из хеадера авторизации
	// так как у гет запроса не должно быть полей body
	// я конечно попробую успеть - но это не факт
	guid, exist := c.Get("guid")
	if !exist {
		log.Printf("ERROR: not authorized user")
		return
	}
	refresh, exist := c.Get("refresh")
	if !exist {
		log.Printf("ERROR: not authorized user")
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"status":  "access",
		"GUID":    guid,
		"refresh": refresh,
	})
}

// @Summary      Refresh JWT and refresh token
// @Description  Refresh JWT and refresh token using the previous refresh token
// @Tags         Auth
// @Produce      json
// @Param Tokens body storage.Tokens true "Tokens"
// @Success      202  {object}  map[string]string  "Tokens successfully refreshed"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Router       /auth/refresh [post]
// @Security     ApiKeyAuth
func RefreshHandler(c *gin.Context) {
	// нужно удалить токен из базы данных
	pass := os.Getenv("POSTGRES_PASSWORD")
	value, exists := c.Get(pass)

	if !exists {
		log.Printf("ERROR: should be a pass for db:")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		return
	}

	bd := value.(*storage.Database)

	secret := os.Getenv("JWTSecretKey")
	m := pkg.Manager{SecretKey: secret}
	guid, exist := c.Get("guid")
	if !exist {
		log.Printf("ERROR: not authorized user")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	GUID := guid.(string)
	newAccessToken, err := m.NewJWT(storage.User{GUID: GUID}, 25*time.Minute)
	if err != nil {
		log.Printf("ERROR: cannot create access token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		storage.DeleteAuth(bd, GUID)
		return
	}
	newRefreshToken, err := m.NewRefreshToken(GUID, time.Duration(time.Hour))
	if err != nil {
		log.Printf("ERROR: cannot create refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		storage.DeleteAuth(bd, GUID)
		return
	}
	hashPass, err := pkg.HashToken(newRefreshToken)
	if err != nil {
		log.Printf("ERROR: cannot create hash from refresh")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		storage.DeleteAuth(bd, GUID)
		return
	}

	// проверяем прошлые данные user-agent и если они не совпадают то запретить - если запрещено - то удалить авторизацию пользователя
	row := bd.BD.QueryRow(`SELECT user_agent FROM auth_users WHERE uuid = $1`, GUID)
	var userAgent string
	err = row.Scan(&userAgent)
	if err != nil {
		log.Printf("ERROR: cannot scan agent %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		storage.DeleteAuth(bd, GUID)
		return
	}

	//

	query := `UPDATE auth_users SET password_hash = $1, expired_at = NOW() + INTERVAL '31 day' WHERE uuid = $2 `
	result, err := bd.BD.Exec(query, hashPass, GUID)
	if err != nil {
		log.Printf("ERROR: cannot update auth_user %v:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot update auth_user"})
		return
	}
	col, err := result.RowsAffected()
	if col > 1 || err != nil{
		log.Printf("ERROR: too much updated value %v:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "too much updated value"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"refresh":   newRefreshToken,
		"authorisation":    newAccessToken,
	})
}



// @Summary      Log out user
// @Description  Delete user's authentication data from the database
// @Tags         Auth
// @Produce      json
// @Param GUID body storage.User true "User UUID"
// @Success      200  {object}  map[string]string  "Successfully logged out"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      500  {object}  map[string]string  "Internal server error"
// @Router       /auth/logout [post]
// @Security     ApiKeyAuth
func LogOutHandler(c *gin.Context){
	value, exist := c.Get("guid")
	if !exist{
		log.Printf("Anuthorized user")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	GUID := value.(string)
	pass := os.Getenv("POSTGRES_PASSWORD")
	database, exist := c.Get(pass)

	if !exist {
		log.Printf("ERROR: should be a pass for db:")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something go wrong"})
		return
	}

	bd := database.(*storage.Database)
	storage.DeleteAuth(bd, GUID)
	c.JSON(http.StatusOK, gin.H{
		"status": "access",
		"logout": GUID,
	})
}
