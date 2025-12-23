package cache

import "checks/pkg/models"

// NoOpStore is a cache implementation that does nothing
// Used when caching is disabled in configuration
type NoOpStore struct{}

// NewNoOpStore creates a new no-operation cache store
func NewNoOpStore() *NoOpStore {
	return &NoOpStore{}
}

// Get always returns cache miss for no-op store
func (n *NoOpStore) Get(domain string) (*models.Report, bool) {
	return nil, false
}

// Set does nothing for no-op store
func (n *NoOpStore) Set(domain string, report *models.Report) {
	// Intentionally empty - no-op
}

// Delete does nothing for no-op store
func (n *NoOpStore) Delete(domain string) {
	// Intentionally empty - no-op
}

// Clear does nothing for no-op store
func (n *NoOpStore) Clear() {
	// Intentionally empty - no-op
}

// Size always returns 0 for no-op store
func (n *NoOpStore) Size() int {
	return 0
}
