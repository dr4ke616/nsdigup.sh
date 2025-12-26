package cache

import (
	"nsdigup/pkg/models"
)

type Store interface {
	Get(domain string) (*models.Report, bool)
	Set(domain string, report *models.Report)
	Delete(domain string)
	Clear()
	Size() int
}
