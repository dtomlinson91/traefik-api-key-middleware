package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

type Config struct {
	HeaderName            string   `json:"headerName,omitempty"`
	Keys                  []string `json:"keys,omitempty"`
	RemoveHeaderOnSuccess bool     `json:"removeHeaderOnSuccess,omitempty"`
}

type Response struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

func CreateConfig() *Config {
	return &Config{
		HeaderName:            "X-API-KEY",
		Keys:                  make([]string, 0),
		RemoveHeaderOnSuccess: true,
	}
}

type KeyAuth struct {
	next                  http.Handler
	headerName            string
	keys                  []string
	removeHeaderOnSuccess bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v, ctx: %+v\n", name, *config, ctx)
	if len(config.Keys) == 0 {
		return nil, fmt.Errorf("must specify at least one valid key")
	}

	return &KeyAuth{
		next:                  next,
		headerName:            config.HeaderName,
		keys:                  config.Keys,
		removeHeaderOnSuccess: config.RemoveHeaderOnSuccess,
	}, nil
}

// contains takes an API key and compares it to the list of valid API keys. The return value notes whether the
// key is in the list or not.
func contains(key string, validKeys []string) bool {
	for _, a := range validKeys {
		if a == key {
			return true
		}
	}
	return false
}

// bearer takes an API key in the `Authorization: Bearer $token` form and compares it to the list of valid keys.
// The token/key is extracted from the header value. The return value notes whether the key is in the list or not.
func bearer(key string, validKeys []string) bool {
	re, _ := regexp.Compile(`Bearer\s(?P<key>[^$]+)`)
	matches := re.FindStringSubmatch(key)

	// If no match found the key is either not valid or in the wrong form.
	if matches == nil {
		return false
	}

	// If found extract the key and compare it to the list of valid keys
	keyIndex := re.SubexpIndex("key")
	extractedKey := matches[keyIndex]
	return contains(extractedKey, validKeys)
}

func (a *KeyAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check headers for valid key
	if contains(req.Header.Get(a.headerName), a.keys) {
		// X-API-KEY header contains a valid key
		if a.removeHeaderOnSuccess {
			req.Header.Del(a.headerName)
		}
		a.next.ServeHTTP(rw, req)
	} else if bearer(req.Header.Get("Authorization"), a.keys) {
		// Authorization header contains a valid Bearer token
		if a.removeHeaderOnSuccess {
			req.Header.Del("Authorization")
		}
		a.next.ServeHTTP(rw, req)
	} else {
		// If no headers or invalid key, return 403
		response := Response{
			Message:    fmt.Sprintf("Invalid API Key. Must pass a valid API Key header using %s: $key or Authorization: Bearer $key", a.headerName),
			StatusCode: http.StatusForbidden,
		}
		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		rw.WriteHeader(response.StatusCode)

		// Send error response
		if err := json.NewEncoder(rw).Encode(response); err != nil {
			// If response cannot be written, log error
			fmt.Printf("Error when sending response to an invalid key: %s", err.Error())
		}
	}
}
