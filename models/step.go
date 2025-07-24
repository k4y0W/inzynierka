package models

type Step struct {
	ID        uint `gorm:"primaryKey"`
	Name      string
	Order     int
	ProcessID uint
}
