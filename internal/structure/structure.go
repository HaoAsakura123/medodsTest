package structure

type User struct {
	Email string `json:"email"`
	GUID  string `json:"uuid" binding:"required"`
}

type Tokens struct {
	RefreshToken string `json:"refresh" binding:"required"`
}
