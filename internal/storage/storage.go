package storage

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/HaoAsakura123/medodsTest/internal/pkg"
	"github.com/HaoAsakura123/medodsTest/internal/structure"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type Database interface {
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Close() error
	Ping() error
}

type PostgresDB struct {
	db *sql.DB
}

func (p *PostgresDB) Query(query string, args ...any) (*sql.Rows, error) {
	return p.db.Query(query, args...)
}

func (p *PostgresDB) Exec(query string, args ...any) (sql.Result, error) {
	return p.db.Exec(query, args...)
}

func (p *PostgresDB) Close() error {
	return p.db.Close()
}

func (p *PostgresDB) Ping() error {
	return p.db.Ping()
}

func (p *PostgresDB) QueryRow(query string, args ...any) *sql.Row {
	return p.db.QueryRow(query, args...)
}

type UserRepository struct {
	db Database
}

func (r *UserRepository) UserExists(guid string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE uuid = $1)`
	var exists bool
	err := r.db.QueryRow(query, guid).Scan(&exists)
	return exists, err
}

func (r *UserRepository) EmailExists(email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
	var exists bool
	err := r.db.QueryRow(query, email).Scan(&exists)
	return exists, err
}

func (r *UserRepository) CreateUser(email, guid string) error {
	_, err := r.db.Exec(`INSERT INTO users (email, uuid) VALUES ($1, $2)`, email, guid)
	return err
}

func (r *UserRepository) SaveRefreshToken(guid, token, userAgent, ip string) error {
	hash, err := pkg.HashToken(token)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(
		`INSERT INTO auth_users 
         (uuid, password_hash, expired_at, user_agent, last_ip, created_at, updated_at)
         VALUES ($1, $2, NOW() + INTERVAL '31 day', $3, $4, NOW(), NOW())`,
		guid, hash, userAgent, ip,
	)
	return err
}

func (r *UserRepository) ValidateRefreshToken(guid, token string) (bool, error) {
	var hash string
	err := r.db.QueryRow(`SELECT password_hash FROM auth_users WHERE uuid = $1`, guid).Scan(&hash)
	if err != nil {
		return false, err
	}
	return pkg.UnhashToken(hash, token) == nil, nil
}

func (r *UserRepository) GetUserAgent(guid string) (string, error) {
	var userAgent string
	err := r.db.QueryRow(
		`SELECT user_agent FROM auth_users WHERE uuid = $1`,
		guid,
	).Scan(&userAgent)
	return userAgent, err
}

func (r *UserRepository) GetLastIP(guid string) (string, error) {
	var ip string
	err := r.db.QueryRow(
		`SELECT last_ip FROM auth_users WHERE uuid = $1`,
		guid,
	).Scan(&ip)
	return ip, err
}

func (r *UserRepository) UpdateLastIP(guid, ip string) error {
	_, err := r.db.Exec(
		`UPDATE auth_users SET last_ip = $1 WHERE uuid = $2`,
		ip, guid,
	)
	return err
}

func (r *UserRepository) GetRefreshToken(guid string) (string, error) {
	var dbHash string

	err := r.db.QueryRow(
		`SELECT password_hash FROM auth_users WHERE uuid = $1`,
		guid,
	).Scan(&dbHash)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("user with guid %s not found", guid)
			return "", fmt.Errorf("user with guid %s not found", guid)
		}
		log.Printf("database error: %v", err)
		return "", fmt.Errorf("database error: %v", err)
	}

	return dbHash, nil
}

// func (r *UserRepository) HashValidate(token, guid string) error {
//     var dbHash string

//     err := r.db.QueryRow(
//         `SELECT password_hash FROM auth_users WHERE uuid = $1`,
//         guid,
//     ).Scan(&dbHash)

//     if err != nil {
//         if err == sql.ErrNoRows {
// 			log.Printf("user with guid %s not found", guid)
//             return fmt.Errorf("user with guid %s not found", guid)
//         }
// 		log.Printf("database error: %v", err)
//         return fmt.Errorf("database error: %v", err)
//     }

//     return nil
// }

func (r *UserRepository) UpdateRefreshToken(guid, token, userAgent string) error {
	hash, err := pkg.HashToken(token)
	if err != nil {
		return err
	}

	//log.Printf("uuid : %s, new hash %s", guid, hash)

	result, err := r.db.Exec(
		`UPDATE auth_users SET password_hash = $1, updated_at = NOW() WHERE uuid = $2 AND user_agent = $3`,
		hash, guid, userAgent,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no rows were updated - user with guid %s and user agent %s not found", guid, userAgent)
	}

	return nil
}

func (r *UserRepository) DeleteAuth(guid string) error {
	result, err := r.db.Exec(`DELETE FROM auth_users WHERE uuid = $1`, guid)
	if err != nil {
		return fmt.Errorf("failed to delete auth record: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("failed to delete rows, human is not exists: %w", err)
	}
	return nil
}

func (r *UserRepository) GetUserByGUID(guid string) (*structure.User, error) {
	var user structure.User

	err := r.db.QueryRow(`SELECT email, uuid FROM users WHERE uuid = $1`, guid).Scan(&user.Email, &user.GUID)
	return &user, err
}

func (r *UserRepository) IsUserAuthorized(guid string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM auth_users WHERE uuid = $1)`,
		guid,
	).Scan(&exists)

	if err != nil {
		return false, fmt.Errorf("database error: %v", err)
	}

	return exists, nil
}

func NewUserRepository(db Database) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Close() error {
	return r.db.Close()
}

const (
	usersTable = `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		uuid UUID NOT NULL UNIQUE
	);`
	authUsersTable = `
	CREATE TABLE IF NOT EXISTS auth_users (
		id SERIAL PRIMARY KEY,
		uuid UUID NOT NULL UNIQUE,
		password_hash VARCHAR(255) NOT NULL,
		expired_at TIMESTAMPTZ NOT NULL,
		user_agent VARCHAR(255) NOT NULL,
    	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_ip VARCHAR(45) NOT NULL
	);`
)

func InitDB() (*UserRepository, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("cannot load .env file: %w", err)
	}

	host := os.Getenv("HOST")
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	dbname := os.Getenv("POSTGRES_DB")

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	sqlDB, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to database: %w", err)
	}

	db := &PostgresDB{db: sqlDB}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("cannot ping database: %w", err)
	}

	log.Println("INFO: Connected to database")

	if err := createTable(db, usersTable); err != nil {
		return nil, fmt.Errorf("cannot create users table: %w", err)
	}

	if err := createTable(db, authUsersTable); err != nil {
		return nil, fmt.Errorf("cannot create auth_users table: %w", err)
	}

	return NewUserRepository(db), nil
}

func createTable(db Database, table string) error {
	_, err := db.Exec(table)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}
	return nil
}

func DeleteAuth(db Database, GUID string) error {
	query := `DELETE FROM auth_users WHERE uuid = $1`
	_, err := db.Exec(query, GUID)
	if err != nil {
		return fmt.Errorf("cannot delete row from table auth_users: %w", err)
	}
	log.Println("Successfully deleted")
	return nil
}
