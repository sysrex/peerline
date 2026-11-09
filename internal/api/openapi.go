package api

import (
	_ "embed"
	"net/http"

	"gopkg.in/yaml.v3"
)

//go:embed openapi.yaml
var openAPISpec []byte

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	var doc any
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}
