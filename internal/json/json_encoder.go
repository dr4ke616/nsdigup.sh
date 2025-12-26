package json

import (
	"encoding/json"
	"io"
)

func GetJsonEncoder(w io.Writer) *json.Encoder {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder
}
