package renderer

import (
	"encoding/json"
	"io"

	"checks/pkg/models"
)

type JSONRenderer struct {
	Indent bool
}

func NewJSONRenderer() *JSONRenderer {
	return &JSONRenderer{Indent: true}
}

func NewJSONRendererCompact() *JSONRenderer {
	return &JSONRenderer{Indent: false}
}

func (j *JSONRenderer) Render(w io.Writer, report *models.Report) error {
	if report == nil {
		return json.NewEncoder(w).Encode(map[string]string{"error": "report cannot be nil"})
	}

	encoder := json.NewEncoder(w)
	if j.Indent {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(report)
}
