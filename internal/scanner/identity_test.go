package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestIdentityScanner_ScanIdentity(t *testing.T) {
	scanner := NewIdentityScanner()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tests := []struct {
		name      string
		domain    string
		wantIP    bool
		wantNS    bool
		wantError bool
	}{
		{
			name:      "Valid domain - google.com",
			domain:    "google.com",
			wantIP:    true,
			wantNS:    true,
			wantError: false,
		},
		{
			name:      "Valid domain - example.com",
			domain:    "example.com",
			wantIP:    true,
			wantNS:    true,
			wantError: false,
		},
		{
			name:      "Invalid domain",
			domain:    "this-domain-does-not-exist-12345.com",
			wantIP:    false,
			wantNS:    false,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := scanner.ScanIdentity(ctx, tt.domain)

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil && !strings.Contains(tt.domain, "not-exist") {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.wantIP && identity.IP == "" {
				t.Errorf("Expected IP address but got empty string")
			}

			if tt.wantNS && len(identity.Nameservers) == 0 {
				t.Errorf("Expected nameservers but got none")
			}

			if identity.IP != "" {
				parts := strings.Split(identity.IP, ".")
				if len(parts) != 4 && !strings.Contains(identity.IP, ":") {
					t.Errorf("Invalid IP format: %s", identity.IP)
				}
			}
		})
	}
}

func TestIdentityScanner_ContextCancellation(t *testing.T) {
	scanner := NewIdentityScanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanner.ScanIdentity(ctx, "google.com")
	if err == nil {
		t.Error("Expected context cancellation error")
	}
}
