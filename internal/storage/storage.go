package storage

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type Database struct {
	BD       *sql.DB
	Password string
}

type User struct {
	Email string `json:"email"`
	GUID  string `json:"uuid" binding:"required"`
}

type Tokens struct {
	Authorisation string `json:"authorisation" binding:"required"`
	Refresh string      `json:"refresh" binding:"required"`
}
const (
	users = `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        uuid UUID NOT NULL UNIQUE
    );`
	auth_users = `
    CREATE TABLE IF NOT EXISTS auth_users (
        id SERIAL PRIMARY KEY,
        uuid UUID NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
		expired_at TIMESTAMPTZ NOT NULL,
		user_agent VARCHAR(255) NOT NULL
    );`
)

func InitBD() (*Database, error) {
	// load from godotenv
	err := godotenv.Load()

	if err != nil {
		log.Printf("ERROR: cannot load .env file: %v", err)
		return nil, err
	}

	host := os.Getenv("HOST")
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	dbname := os.Getenv("POSTGRES_DB")

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)

	if err != nil {
		log.Printf("ERROR: cannot connect to database: %v", err)
		return nil, err
	}

	//defer db.Close()
	err = db.Ping()
	if err != nil {
		log.Printf("ERROR: cannot connect to database: %v", err)
		return nil, err
	}
	log.Printf("INFO: Connected to database")
	//create tables
	err = createTable(db, users)
	if err != nil {
		log.Printf("ERROR: cannot create table: %v", err)
		return nil, err
	}
	err = createTable(db, auth_users)
	if err != nil {
		log.Printf("ERROR: cannot create table: %v", err)
		return nil, err
	}
	return &Database{BD: db, Password: password}, nil
}

func createTable(db *sql.DB, table string) error {
	_, err := db.Exec(table)
	if err != nil {
		log.Fatal("ERROR: Failed to create table:", err)
		return err
	}
	return nil
}

func (D *Database) CloseDB() {
	D.BD.Close()
}

func DeleteAuth(db *Database, GUID string){
	query := `DELETE FROM auth_users WHERE uuid = $1`
	_, err := db.BD.Exec(query, GUID)
	if err != nil{
		log.Printf("ERROR: cannot delete row from table auth_users %v", err)
		return
	}
	log.Printf("Succesion delete")
}

