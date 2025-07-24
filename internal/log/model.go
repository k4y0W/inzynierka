package models

import "time"

type Log struct {
	ID       uint      `gorm:"primaryKey"`
	Username string    `gorm:"not null"`
	Date     time.Time `gorm:"not null"`
}
