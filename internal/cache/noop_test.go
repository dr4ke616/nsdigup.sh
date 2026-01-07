package cache

import "context"

import (
	"testing"
	"time"

	"nsdigup/pkg/models"
)

func TestNoOpStore_Get(t *testing.T) {
	store := NewNoOpStore()

	report, found := store.Get(context.Background(), "example.com")

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
	store.Set(context.Background(), "example.com", report)

	// Should still return cache miss
	_, found := store.Get(context.Background(), "example.com")
	if found {
		t.Error("NoOpStore should not store anything")
	}
}

func TestNoOpStore_Interface(t *testing.T) {
	var store Store = NewNoOpStore()

	// Verify it implements the Store interface
	_ = store
}
