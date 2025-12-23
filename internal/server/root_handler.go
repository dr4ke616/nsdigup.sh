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
	address := h.config.App.AdvertisedAddress

	output := banner.AsciiBanner + "\n\n"

	output += "Features:\n"
	output += "  • DNS Resolution & Nameserver Analysis\n"
	output += "  • SSL/TLS Certificate Information & Expiry\n"
	output += "  • Email Security (SPF/DMARC) Validation\n"
	output += "  • HTTP Security Headers Assessment\n\n"

	output += "Usage:\n"
	output += "  curl " + address + "/<domain>\n\n"

	output += "Examples:\n"
	output += "  curl " + address + "/google.com\n"
	output += "  curl " + address + "/github.com\n"
	output += "  curl " + address + "/example.com\n\n"

	output += "Output Formats:\n"
	output += "  Text (default): curl " + address + "/google.com\n"
	output += "  JSON (header):  curl -H \"Accept: application/json\" " + address + "/google.com\n\n"

	output += "\n"

	fmt.Fprint(w, output)
}

func (h *Handler) writeHomeJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"name": "checks.sh",
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(response)
}
