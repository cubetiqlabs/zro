package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerTransportOnlyTargetsPlaneHost(t *testing.T) {
	var got string
	plane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") }))
	defer plane.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("token leaked to a foreign host")
		}
	}))
	defer other.Close()

	token := ""
	c := &http.Client{Transport: NewBearerTransport(nil, plane.URL, func() string { return token })}

	_, _ = c.Get(plane.URL)
	if got != "" {
		t.Fatalf("no token yet, got %q", got)
	}
	token = "zro_node_x"
	_, _ = c.Get(plane.URL)
	if got != "Bearer zro_node_x" {
		t.Fatalf("expected bearer header, got %q", got)
	}
	_, _ = c.Get(other.URL)
}
