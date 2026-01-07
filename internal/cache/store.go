package cache

import (
	"context"

	"nsdigup/pkg/models"
)

type Store interface {
	Get(ctx context.Context, domain string) (*models.Report, bool)
	Set(ctx context.Context, domain string, report *models.Report)
}
