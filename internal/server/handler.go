package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"checks/pkg/models"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := extractDomain(r.URL.Path)
	if domain == "" {
		http.Error(w, "No domain specified", http.StatusBadRequest)
		return
	}

	report := &models.Report{
		Target:    domain,
		Timestamp: time.Now(),
		Identity: models.Identity{
			IP:          "",
			Registrar:   "",
			Owner:       "",
			ExpiresDays: 0,
			Nameservers: []string{},
		},
		Certificates: models.CertData{
			Current: models.CertDetails{},
			History: []models.CertDetails{},
		},
		Misconfigurations: models.Misconfigurations{
			DNSGlue: []string{},
			EmailSec: models.EmailSec{
				DMARC:  "",
				SPF:    "",
				IsWeak: false,
			},
			Headers: []string{},
		},
		HTTP: models.HTTPDetails{
			StatusCode: 0,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func extractDomain(path string) string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return ""
	}
	return path
}