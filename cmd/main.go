package main

import (
	"github.com/HaoAsakura123/medodsTest/internal/app"
)

//	@title			TODO App API
//	@version		1.0
//	@description	API server for authorisation
//	@termsOfService	http://swagger.io/terms/

//	@contact.name	API Support
//	@contact.email	support@example.com

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

//	@host		localhost:8080
//	@BasePath	/
//	@schemes	http

//	@securityDefinitions.apiKey	ApiKeyAuth
//	@in							header
//	@name						Authorization

func main() {
	app.InitRouter()
}
