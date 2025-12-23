package cache

import (
	"sync"
	"time"

	"checks/pkg/models"
)

type Store interface {
	Get(domain string) (*models.Report, bool)
	Set(domain string, report *models.Report)
	Delete(domain string)
	Clear()
	Size() int
}

type cacheEntry struct {
	report    *models.Report
	timestamp time.Time
	ttl       time.Duration
}

func (e *cacheEntry) isExpired() bool {
	if e.ttl == 0 {
		return false
	}
	return time.Since(e.timestamp) > e.ttl
}

type MemoryStore struct {
	entries map[string]*cacheEntry
	mutex   sync.RWMutex
	ttl     time.Duration
}

func NewMemoryStore(ttl time.Duration) *MemoryStore {
	store := &MemoryStore{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
	
	if ttl > 0 {
		go store.cleanupExpired()
	}
	
	return store
}

func (m *MemoryStore) Get(domain string) (*models.Report, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	entry, exists := m.entries[domain]
	if !exists {
		return nil, false
	}
	
	if entry.isExpired() {
		m.mutex.RUnlock()
		m.mutex.Lock()
		delete(m.entries, domain)
		m.mutex.Unlock()
		m.mutex.RLock()
		return nil, false
	}
	
	return entry.report, true
}

func (m *MemoryStore) Set(domain string, report *models.Report) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.entries[domain] = &cacheEntry{
		report:    report,
		timestamp: time.Now(),
		ttl:       m.ttl,
	}
}

func (m *MemoryStore) Delete(domain string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	delete(m.entries, domain)
}

func (m *MemoryStore) Clear() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.entries = make(map[string]*cacheEntry)
}

func (m *MemoryStore) Size() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	return len(m.entries)
}

func (m *MemoryStore) cleanupExpired() {
	ticker := time.NewTicker(m.ttl / 2)
	defer ticker.Stop()
	
	for range ticker.C {
		m.mutex.Lock()
		now := time.Now()
		for domain, entry := range m.entries {
			if entry.ttl > 0 && now.Sub(entry.timestamp) > entry.ttl {
				delete(m.entries, domain)
			}
		}
		m.mutex.Unlock()
	}
}