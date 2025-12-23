package cache

import "checks/pkg/models"

type NoOpStore struct{}

func NewNoOpStore() *NoOpStore {
	return &NoOpStore{}
}

func (n *NoOpStore) Get(domain string) (*models.Report, bool) {
	// Get always returns cache miss for no-op store
	return nil, false
}

func (n *NoOpStore) Set(domain string, report *models.Report) {
	// Set does nothing for no-op store
}

func (n *NoOpStore) Delete(domain string) {
	// Delete does nothing for no-op store
}

func (n *NoOpStore) Clear() {
	// Clear does nothing for no-op store
}

func (n *NoOpStore) Size() int {
	return 0
}
