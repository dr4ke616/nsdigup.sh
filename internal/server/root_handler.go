package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"checks/internal/banner"
)

// ServeHome handles the root "/" route
func (h *Handler) ServeHome(w http.ResponseWriter, r *http.Request) {
	format := h.getOutputFormat(r)

	switch format {
	case "ansi", "text":
		h.writeHomeANSI(w)
	default: // json
		h.writeHomeJSON(w)
	}
}

func (h *Handler) writeHomeANSI(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	output := banner.Generate(h.config.App.Name) + "\n\n"

	output += fmt.Sprintf("\033[1m\033[32m%s\033[0m - Domain Health Checker\n\n", h.config.App.Name)

	output += "\033[1mUsage:\033[0m\n"
	output += "  curl " + h.getBaseURL() + "/<domain>\n\n"

	output += "\033[1mExamples:\033[0m\n"
	output += "  curl " + h.getBaseURL() + "/google.com\n"
	output += "  curl " + h.getBaseURL() + "/github.com\n"
	output += "  curl " + h.getBaseURL() + "/example.com\n\n"

	output += "\033[1mOutput Formats:\033[0m\n"
	output += "  Text (default): curl " + h.getBaseURL() + "/google.com\n"
	output += "  JSON:           curl " + h.getBaseURL() + "/google.com?format=json\n"
	output += "  JSON (header):  curl -H \"Accept: application/json\" " + h.getBaseURL() + "/google.com\n\n"

	output += "\033[1mFeatures:\033[0m\n"
	output += "  • DNS Resolution & Nameserver Analysis\n"
	output += "  • SSL/TLS Certificate Information & Expiry\n"
	output += "  • Email Security (SPF/DMARC) Validation\n"
	output += "  • HTTP Security Headers Assessment\n"
	output += "  • Colorized Terminal Output\n"
	if h.config.Cache.Enabled {
		output += fmt.Sprintf("  • In-Memory Caching (%v TTL)\n", h.config.Cache.TTL)
	} else {
		output += "  • Real-time Scanning (no caching)\n"
	}
	output += "\n"

	fmt.Fprint(w, output)
}

func (h *Handler) writeHomeJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"name":        h.config.App.Name,
		"description": "Domain Health Checker",
		"usage":       h.getBaseURL() + "/<domain>",
		"examples": []string{
			h.getBaseURL() + "/google.com",
			h.getBaseURL() + "/github.com",
			h.getBaseURL() + "/example.com",
		},
		"formats": map[string]string{
			"text": h.getBaseURL() + "/google.com",
			"json": h.getBaseURL() + "/google.com?format=json",
		},
		"features": []string{
			"DNS Resolution & Nameserver Analysis",
			"SSL/TLS Certificate Information & Expiry",
			"Email Security (SPF/DMARC) Validation",
			"HTTP Security Headers Assessment",
			"Colorized Terminal Output",
		},
		"cache": map[string]interface{}{
			"enabled": h.config.Cache.Enabled,
			"ttl":     h.config.Cache.TTL.String(),
		},
	}

	// Use standard JSON encoding for home page
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(response)
}
