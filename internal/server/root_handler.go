package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"nsdigup/internal/json"
	"strings"

	"nsdigup/internal/banner"
)

// ServeHome handles the root "/" route
func (h *Handler) ServeHome(w http.ResponseWriter, r *http.Request) {
	format := h.getOutputFormat(r)
	h.logger.Debug("serving home page", slog.String("format", format.String()))

	switch format {
	case OutputFormatANSI:
		h.writeHomeANSI(w, r)
	case OutputFormatJSON:
		h.writeHomeJSON(w)
	default:
		// This should never happen if OutputFormat enum is properly maintained
		panic(fmt.Sprintf("unsupported output format: %v", format))
	}
}

func (h *Handler) writeHomeANSI(w http.ResponseWriter, r *http.Request) {
	address := h.config.App.AdvertisedAddress
	bannerText := banner.GetAsciBanner()

	content := "Features:\n"
	content += "  • DNS Resolution & Nameserver Analysis\n"
	content += "  • SSL/TLS Certificate Information & Expiry\n"
	content += "  • Email Security (SPF/DMARC) Validation\n"
	content += "  • HTTP Security Headers Assessment\n\n"

	content += "Usage:\n"
	content += "  curl " + address + "/<domain>\n\n"

	content += "Examples:\n"
	content += "  curl " + address + "/google.com\n"
	content += "  curl " + address + "/github.com\n"
	content += "  curl " + address + "/example.com\n\n"

	content += "Output Formats:\n"
	content += "  Text (default): curl " + address + "/google.com\n"
	content += "  JSON (header):  curl -H \"Accept: application/json\" " + address + "/google.com\n\n"

	content += "\n"

	if h.isBrowser(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		fmt.Fprint(w, h.renderBrowserHTML(bannerText, content))
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		fmt.Fprint(w, bannerText+"\n\n"+content)
	}
}

func (h *Handler) isBrowser(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")
	return !strings.HasPrefix(userAgent, "curl/") &&
		!strings.HasPrefix(userAgent, "Wget/") &&
		!strings.HasPrefix(userAgent, "HTTPie/") &&
		userAgent != ""
}

func (h *Handler) renderBrowserHTML(bannerText, content string) string {
	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>nsdigup.sh</title>
    <style>
        body { font-family: monospace; background: #141414; color: #d4d4d4; padding: 20px; }
        .search-box { margin: 20px 0; }
        input { padding: 8px; font-size: 14px; width: 300px; }
        button { padding: 8px 16px; font-size: 14px; cursor: pointer; }
        pre { white-space: pre-wrap; word-wrap: break-word; margin: 0; }
    </style>
</head>
<body>
    <pre>` + bannerText + `</pre>
    <div class="search-box">
        <form onsubmit="event.preventDefault(); window.location.href='/' + document.getElementById('domain').value;">
            <input type="text" id="domain" placeholder="Enter domain (e.g., google.com)" required>
            <button type="submit">Analyze</button>
        </form>
    </div>
    <pre>` + content + `</pre>
</body>
</html>`
}

func (h *Handler) writeHomeJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	response := map[string]interface{}{
		"name": "nsdigup.sh",
	}
	json.GetJsonEncoder(w).Encode(response)
}
