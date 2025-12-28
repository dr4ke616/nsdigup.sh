package server

import (
	"net/http"
	"nsdigup/internal/json"
)

var ok = map[string]string{
	"status": "ok",
}

// ServeHealth handles the "/health" route
func (h *Handler) ServeHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.GetJsonEncoder(w).Encode(ok)
}
