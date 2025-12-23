package cache

import (
	"testing"
	"time"

	"checks/pkg/models"
)

func TestNoOpStore_Get(t *testing.T) {
	store := NewNoOpStore()

	report, found := store.Get("example.com")

	if found {
		t.Error("NoOpStore should never return found=true")
	}

	if report != nil {
		t.Error("NoOpStore should never return a report")
	}
}

func TestNoOpStore_Set(t *testing.T) {
	store := NewNoOpStore()

	report := &models.Report{
		Target:    "example.com",
		Timestamp: time.Now(),
	}

	// Should not panic or error
	store.Set("example.com", report)

	// Should still return cache miss
	_, found := store.Get("example.com")
	if found {
		t.Error("NoOpStore should not store anything")
	}
}

func TestNoOpStore_Delete(t *testing.T) {
	store := NewNoOpStore()

	// Should not panic or error
	store.Delete("example.com")
}

func TestNoOpStore_Clear(t *testing.T) {
	store := NewNoOpStore()

	// Should not panic or error
	store.Clear()
}

func TestNoOpStore_Size(t *testing.T) {
	store := NewNoOpStore()

	if store.Size() != 0 {
		t.Errorf("NoOpStore size should always be 0, got %d", store.Size())
	}

	// Even after operations, size should remain 0
	report := &models.Report{Target: "test.com"}
	store.Set("test.com", report)

	if store.Size() != 0 {
		t.Errorf("NoOpStore size should remain 0 after operations, got %d", store.Size())
	}
}

func TestNoOpStore_Interface(t *testing.T) {
	var store Store = NewNoOpStore()

	// Verify it implements the Store interface
	_ = store
}
