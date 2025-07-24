package models

type Process struct {
	ID     uint   `gorm:"primaryKey"`
	Name   string `gorm:"not null"`
	Status string

	Steps []Step `gorm:"foreignKey:ProcessID"` // Powiązanie 1:N
}
