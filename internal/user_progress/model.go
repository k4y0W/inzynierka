package models

import "time"

type UserProgress struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint
	StepID    uint
	IsDone    bool
	StartedAt time.Time
	EndedAt   time.Time

	// Relacje (opcjonalnie)
	User User `gorm:"foreignKey:UserID"`
	Step Step `gorm:"foreignKey:StepID"`
}
