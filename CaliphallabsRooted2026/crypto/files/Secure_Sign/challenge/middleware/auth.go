package middleware

import (
	"secure-sign/database"
	"secure-sign/models"

	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func IsAuthenticated(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")

	if cookie == "" {
		headers := c.GetReqHeaders()

		if len(headers["Authorization"]) > 0 {
			auth := headers["Authorization"][0]

			if len(auth) > 7 && auth[:7] == "Bearer " {
				cookie = auth[7:]
			}
		}
	}

	if cookie == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "unauthenticated"})
	}

	token, err := jwt.Parse(cookie, func(token *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "unauthenticated"})
	}

	claims := token.Claims.(jwt.MapClaims)
	userId := claims["iss"]

	var user models.User
	database.DB.Where("id = ?", userId).First(&user)

	return c.Next()
}
