package models

import "time"

// Status constants for certificates and domain expiration tracking.
const (
	StatusActive       = "Active"
	StatusExpired      = "Expired"
	StatusExpiringSoon = "Expiring Soon"
)

// ExpirationThresholdDays is the number of days before expiration
// when the status changes from Active to Expiring Soon.
const ExpirationThresholdDays = 30

// CalculateExpirationStatus determines the status based on an expiration timestamp.
// It returns:
// - StatusExpired if the timestamp is in the past
// - StatusExpiringSoon if the timestamp is within ExpirationThresholdDays
// - StatusActive otherwise
func CalculateExpirationStatus(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return StatusActive
	}

	now := time.Now()
	if now.After(expiresAt) {
		return StatusExpired
	}

	thresholdTime := now.Add(ExpirationThresholdDays * 24 * time.Hour)
	if thresholdTime.After(expiresAt) {
		return StatusExpiringSoon
	}

	return StatusActive
}

// CalculateDaysUntilExpiration calculates the number of days until expiration.
// Returns negative days if already expired.
func CalculateDaysUntilExpiration(expiresAt time.Time) int {
	if expiresAt.IsZero() {
		return 0
	}
	return int(time.Until(expiresAt).Hours() / 24)
}
