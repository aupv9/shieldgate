package database

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

func TestGormLogLevel_StatementsOnlyWhenDebugging(t *testing.T) {
	tests := []struct {
		level logrus.Level
		want  logger.LogLevel
	}{
		{logrus.TraceLevel, logger.Info},
		{logrus.DebugLevel, logger.Info},
		{logrus.InfoLevel, logger.Warn},
		{logrus.WarnLevel, logger.Warn},
		{logrus.ErrorLevel, logger.Error},
	}
	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			// Act & Assert
			assert.Equal(t, tt.want, gormLogLevel(tt.level))
		})
	}
}
