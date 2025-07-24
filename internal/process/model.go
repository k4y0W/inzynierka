package models

type Process struct {
	ID     uint   `gorm:"primaryKey"`
	Name   string `gorm:"not null"`
	Status string `gorm:"not null"`
	Steps []Step `gorm:"foreignKey:ProcessID"` // Powiązanie 1:N
}

package models

type Step struct {
	ID        uint `gorm:"primaryKey"`
	Name      string
	Order     int
	ProcessID uint
}
