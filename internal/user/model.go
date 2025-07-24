package models

import "time"

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Email     string `gorm:"unique;not null"`
	Username  string `gorm:"unique;not null"`
	Name      string
	LastName  string
	Indeks    int
	Password  string `gorm:"not null"`
	CreatedAt time.Time
}
