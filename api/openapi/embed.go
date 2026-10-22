// Package openapi embeds the control plane's OpenAPI document so the plane can
// serve exactly the spec it was built with.
package openapi

import _ "embed"

// Spec is the OpenAPI 3.1 document in YAML.
//
//go:embed openapi.yaml
var Spec []byte
