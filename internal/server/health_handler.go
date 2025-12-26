package server

import (
	"net/http"
	"nsdigup/internal/json"
)

// ServeHealth handles the "/health" route
func (h *Handler) ServeHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	response := map[string]string{
		"status": "ok",
	}
	json.GetJsonEncoder(w).Encode(response)
}
