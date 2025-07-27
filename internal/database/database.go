package database

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"shield1/internal/models"
)

// Initialize initializes the database connection using GORM
func Initialize(databaseURL string) (*gorm.DB, error) {
	logrus.Info("Connecting to database...")

	// Configure GORM logger
	gormLogger := logger.Default.LogMode(logger.Info)

	// Open database connection with GORM
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Get underlying sql.DB to configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)

	logrus.Info("Database connection established")
	return db, nil
}

// Migrate runs database migrations using GORM AutoMigrate
func Migrate(db *gorm.DB) error {
	logrus.Info("Running database migrations...")

	// AutoMigrate will create tables, missing columns, missing indexes
	// and won't delete unused columns to protect your data
	err := db.AutoMigrate(
		&models.User{},
		&models.Client{},
		&models.AuthorizationCode{},
		&models.AccessToken{},
		&models.RefreshToken{},
	)
	if err != nil {
		return fmt.Errorf("failed to run database migrations: %w", err)
	}

	logrus.Info("Database migrations completed successfully")
	return nil
}
