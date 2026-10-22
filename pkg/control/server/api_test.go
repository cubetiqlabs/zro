package server

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cubetiqlabs/zro/api/openapi"
	"go.yaml.in/yaml/v3"
)

// Every REST route registered in server.go must be described in the OpenAPI
// document (and the document may not describe routes that do not exist), so
// the spec cannot drift from the server.
func TestOpenAPICoversEveryRoute(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openapi.Spec, &doc); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}
	spec := map[string]bool{}
	for path, ops := range doc.Paths {
		for method := range ops {
			if method != "parameters" {
				spec[strings.ToUpper(method)+" "+path] = true
			}
		}
	}

	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	// Method-less patterns (the WebSocket hub) are served for GET.
	re := regexp.MustCompile(`s\.mux\.HandleFunc\("(?:([A-Z]+) )?(/[^"]*)"`)
	code := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		method, path := m[1], m[2]
		if path == "/" || path == "/ws/v1/events" { // gateway fallback; documented alias of /api/v1/ws
			continue
		}
		if method == "" {
			method = "GET"
		}
		code[method+" "+path] = true
	}
	for r := range code {
		if !spec[r] {
			t.Errorf("route %s is not in api/openapi/openapi.yaml", r)
		}
	}
	for r := range spec {
		if !code[r] {
			t.Errorf("openapi.yaml documents %s, which the server does not register", r)
		}
	}
}
