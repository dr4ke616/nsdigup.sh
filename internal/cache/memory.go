package cache

import (
	"log/slog"
	"sync"
	"time"

	"checks/internal/logger"
	"checks/pkg/models"
)

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
		logger.Get().Debug("cache miss",
			slog.String("domain", domain),
			slog.String("reason", "not_found"))
		return nil, false
	}

	if entry.isExpired() {
		age := time.Since(entry.timestamp)
		logger.Get().Debug("cache miss",
			slog.String("domain", domain),
			slog.String("reason", "expired"),
			slog.Duration("age", age))

		m.mutex.RUnlock()
		m.mutex.Lock()
		delete(m.entries, domain)
		m.mutex.Unlock()
		m.mutex.RLock()
		return nil, false
	}

	age := time.Since(entry.timestamp)
	logger.Get().Debug("cache hit",
		slog.String("domain", domain),
		slog.Duration("age", age),
		slog.Duration("remaining_ttl", m.ttl-age))

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

	logger.Get().Debug("cache set",
		slog.String("domain", domain),
		slog.Int("total_entries", len(m.entries)))
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
		removed := 0
		for domain, entry := range m.entries {
			if entry.ttl > 0 && now.Sub(entry.timestamp) > entry.ttl {
				delete(m.entries, domain)
				removed++
			}
		}
		remaining := len(m.entries)
		m.mutex.Unlock()

		if removed > 0 {
			logger.Get().Debug("cache cleanup completed",
				slog.Int("removed", removed),
				slog.Int("remaining", remaining))
		}
	}
}
