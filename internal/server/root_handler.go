package server

import (
	"checks/internal/json"
	"fmt"
	"log/slog"
	"net/http"

	"checks/internal/banner"
)

// ServeHome handles the root "/" route
func (h *Handler) ServeHome(w http.ResponseWriter, r *http.Request) {
	format := h.getOutputFormat(r)
	h.logger.Debug("serving home page", slog.String("format", format.String()))

	switch format {
	case OutputFormatANSI:
		h.writeHomeANSI(w)
	case OutputFormatJSON:
		h.writeHomeJSON(w)
	default:
		// This should never happen if OutputFormat enum is properly maintained
		panic(fmt.Sprintf("unsupported output format: %v", format))
	}
}

func (h *Handler) writeHomeANSI(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	address := h.config.App.AdvertisedAddress

	output := banner.GetAsciBanner() + "\n\n"

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
	w.WriteHeader(200)
	response := map[string]interface{}{
		"name": "checks.sh",
	}
	json.GetJsonEncoder(w).Encode(response)
}
