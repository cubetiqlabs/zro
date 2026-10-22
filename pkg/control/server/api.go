package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
)

// Every error the REST API returns has this shape, so clients (and the web UI)
// parse one format: {"error":{"code":"not_found","message":"...","request_id":"..."}}.
type errorBody struct {
	Error apiErrorDetail `json:"error"`
}

type apiErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

var statusCodes = map[int]string{
	http.StatusBadRequest:          "invalid_request",
	http.StatusUnauthorized:        "unauthorized",
	http.StatusForbidden:           "forbidden",
	http.StatusNotFound:            "not_found",
	http.StatusConflict:            "conflict",
	http.StatusTooManyRequests:     "rate_limited",
	http.StatusInternalServerError: "internal",
}

// apiError writes the standard JSON error envelope.
func apiError(w http.ResponseWriter, message string, status int) {
	code := statusCodes[status]
	if code == "" {
		code = "error"
	}
	writeJSON(w, status, errorBody{apiErrorDetail{Code: code, Message: message, RequestID: w.Header().Get("X-Request-ID")}})
}

// withRequestID tags every request/response with an X-Request-ID, honoring a
// caller-supplied one so a request can be traced across a proxy.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 64 {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

// Page is the envelope of every paginated list.
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"` // pass as ?cursor= for the next page; empty on the last
}

const (
	defaultPageSize = 100
	maxPageSize     = 500
)

// writePage serves items as one page selected by ?limit= and ?cursor=.
// ponytail: slices an already-loaded list (cursor = offset); push LIMIT into
// the repositories if a tenant's lists ever grow large.
func writePage[T any](w http.ResponseWriter, r *http.Request, items []T) {
	limit := defaultPageSize
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxPageSize {
			apiError(w, "limit must be between 1 and "+strconv.Itoa(maxPageSize), http.StatusBadRequest)
			return
		}
		limit = n
	}
	offset := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		raw, err := base64.RawURLEncoding.DecodeString(c)
		offset, _ = strconv.Atoi(string(raw))
		if err != nil || offset < 0 {
			apiError(w, "invalid cursor", http.StatusBadRequest)
			return
		}
	}
	page := Page[T]{Items: []T{}}
	if offset < len(items) {
		end := min(offset+limit, len(items))
		page.Items = items[offset:end]
		if end < len(items) {
			page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
		}
	}
	writeJSON(w, http.StatusOK, page)
}
