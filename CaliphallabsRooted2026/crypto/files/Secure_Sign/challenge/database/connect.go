package database

import (
	"secure-sign/models"

	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	var err error

	DB, err = gorm.Open(sqlite.Open("database.sqlite"), &gorm.Config{})

	if err != nil {
		log.Panic("Could not connect to the database: ", err)
	}

	DB.AutoMigrate(&models.User{})
}
