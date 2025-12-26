package renderer

import (
	"io"

	"checks/internal/json"
	"checks/pkg/models"
)

type JSONRenderer struct {
}

func NewJSONRenderer() *JSONRenderer {
	return &JSONRenderer{}
}

func (j *JSONRenderer) Render(w io.Writer, report *models.Report) error {
	encoder := json.GetJsonEncoder(w)
	if report == nil {
		return encoder.Encode(map[string]string{"error": "report cannot be nil"})
	}

	return encoder.Encode(report)
}
