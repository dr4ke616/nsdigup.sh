package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"nsdigup/pkg/models"
)

func TestMemoryStore_BasicOperations(t *testing.T) {
	store := NewMemoryStore(0) // No TTL for basic tests

	domain := "example.com"
	report := &models.Report{
		Target:    domain,
		Timestamp: time.Now(),
		Identity: models.Identity{
			IP: "192.168.1.1",
		},
	}

	// Test Get on empty cache
	_, exists := store.Get(context.Background(), domain)
	if exists {
		t.Error("Expected no entry for domain in empty cache")
	}

	// Test Set
	store.Set(context.Background(), domain, report)

	// Test Get after Set
	cachedReport, exists := store.Get(context.Background(), domain)
	if !exists {
		t.Error("Expected entry to exist after Set")
	}

	if cachedReport.Target != domain {
		t.Errorf("Expected target %s, got %s", domain, cachedReport.Target)
	}

	if cachedReport.Identity.IP != report.Identity.IP {
		t.Errorf("Expected IP %s, got %s", report.Identity.IP, cachedReport.Identity.IP)
	}

	// Test Size
	if store.Size() != 1 {
		t.Errorf("Expected size 1, got %d", store.Size())
	}

	// Test Delete
	store.Delete(domain)
	_, exists = store.Get(context.Background(), domain)
	if exists {
		t.Error("Expected no entry after Delete")
	}

	if store.Size() != 0 {
		t.Errorf("Expected size 0 after delete, got %d", store.Size())
	}
}

func TestMemoryStore_Clear(t *testing.T) {
	store := NewMemoryStore(0)

	// Add multiple entries
	domains := []string{"example.com", "google.com", "github.com"}
	for _, domain := range domains {
		report := &models.Report{Target: domain}
		store.Set(context.Background(), domain, report)
	}

	if store.Size() != len(domains) {
		t.Errorf("Expected size %d, got %d", len(domains), store.Size())
	}

	// Clear all entries
	store.Clear()

	if store.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", store.Size())
	}

	// Verify all entries are gone
	for _, domain := range domains {
		_, exists := store.Get(context.Background(), domain)
		if exists {
			t.Errorf("Expected no entry for %s after clear", domain)
		}
	}
}

func TestMemoryStore_TTL(t *testing.T) {
	ttl := 100 * time.Millisecond
	store := NewMemoryStore(ttl)

	domain := "example.com"
	report := &models.Report{Target: domain}

	// Set entry
	store.Set(context.Background(), domain, report)

	// Should exist immediately
	_, exists := store.Get(context.Background(), domain)
	if !exists {
		t.Error("Expected entry to exist immediately after set")
	}

	// Should still exist before TTL
	time.Sleep(ttl / 2)
	_, exists = store.Get(context.Background(), domain)
	if !exists {
		t.Error("Expected entry to exist before TTL expiry")
	}

	// Should be expired after TTL
	time.Sleep(ttl)
	_, exists = store.Get(context.Background(), domain)
	if exists {
		t.Error("Expected entry to be expired after TTL")
	}

	// Size should reflect expired entry removal
	if store.Size() != 0 {
		t.Errorf("Expected size 0 after TTL expiry, got %d", store.Size())
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStore(0)

	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				domain := formatDomain(id, j)
				report := &models.Report{Target: domain}
				store.Set(context.Background(), domain, report)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				domain := formatDomain(id, j)
				store.Get(context.Background(), domain)
			}
		}(i)
	}

	wg.Wait()

	expectedSize := numGoroutines * numOperations
	actualSize := store.Size()

	if actualSize != expectedSize {
		t.Errorf("Expected size %d after concurrent operations, got %d", expectedSize, actualSize)
	}
}

func TestMemoryStore_UpdateExisting(t *testing.T) {
	store := NewMemoryStore(0)

	domain := "example.com"

	// Set initial report
	report1 := &models.Report{
		Target:   domain,
		Identity: models.Identity{IP: "192.168.1.1"},
	}
	store.Set(context.Background(), domain, report1)

	// Update with new report
	report2 := &models.Report{
		Target:   domain,
		Identity: models.Identity{IP: "192.168.1.2"},
	}
	store.Set(context.Background(), domain, report2)

	// Should have updated IP
	cachedReport, exists := store.Get(context.Background(), domain)
	if !exists {
		t.Error("Expected entry to exist after update")
	}

	if cachedReport.Identity.IP != "192.168.1.2" {
		t.Errorf("Expected updated IP 192.168.1.2, got %s", cachedReport.Identity.IP)
	}

	// Size should still be 1
	if store.Size() != 1 {
		t.Errorf("Expected size 1 after update, got %d", store.Size())
	}
}

func TestMemoryStore_ZeroTTL(t *testing.T) {
	store := NewMemoryStore(0) // Zero TTL means no expiration

	domain := "example.com"
	report := &models.Report{Target: domain}

	store.Set(context.Background(), domain, report)

	// Should exist after a long time with zero TTL
	time.Sleep(10 * time.Millisecond)
	_, exists := store.Get(context.Background(), domain)
	if !exists {
		t.Error("Expected entry to exist with zero TTL (no expiration)")
	}
}

// Helper function to format domain names for testing
func formatDomain(id1, id2 int) string {
	return "example" + itoa(id1) + "-" + itoa(id2) + ".com"
}

// Simple integer to string conversion
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	negative := i < 0
	if negative {
		i = -i
	}

	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}

	if negative {
		digits = append([]byte{'-'}, digits...)
	}

	return string(digits)
}
