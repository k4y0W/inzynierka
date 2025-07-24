package models

type StepNote struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	Username string
	Process  string
}
