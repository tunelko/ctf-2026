package main

import (
	"secure-sign/database"
	"secure-sign/handlers"
	"secure-sign/middleware"
	"secure-sign/utils"

	"github.com/gofiber/fiber/v2"
)

func main() {
	database.Connect()
	utils.LoadOrGenerateKeys()

	app := fiber.New()

	app.Static("/", "./public")

	routes(app)

	app.Listen(":7000")
}

func routes(app *fiber.App) {
	app.Post("/api/register", handlers.Register)
	app.Post("/api/login", handlers.Login)

	app.Post("/api/verify", handlers.VerifySignature)

	app.Use(middleware.IsAuthenticated)

	app.Get("/api/user", handlers.User)
	app.Post("/api/sign", handlers.SignDocument)
}
