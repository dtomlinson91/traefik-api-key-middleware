package traefik_api_key_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

type Config struct {
	AuthenticationHeader     bool     `json:"authenticationHeader,omitempty"`
	AuthenticationHeaderName string   `json:"headerName,omitempty"`
	BearerHeader             bool     `json:"bearerHeader,omitempty"`
	BearerHeaderName         string   `json:"bearerHeaderName,omitempty"`
	QueryParam               bool     `json:"queryParam,omitempty"`
	QueryParamName           string   `json:"queryParamName,omitempty"`
	Keys                     []string `json:"keys,omitempty"`
	RemoveHeadersOnSuccess   bool     `json:"removeHeadersOnSuccess,omitempty"`
}

type Response struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

func CreateConfig() *Config {
	return &Config{
		AuthenticationHeader:     true,
		AuthenticationHeaderName: "X-API-KEY",
		BearerHeader:             true,
		BearerHeaderName:         "Authorization",
		QueryParam:               true,
		QueryParamName:           "code",
		Keys:                     make([]string, 0),
		RemoveHeadersOnSuccess:   true,
	}
}

type KeyAuth struct {
	next                     http.Handler
	authenticationHeader     bool
	authenticationHeaderName string
	bearerHeader             bool
	bearerHeaderName         string
	queryParam               bool
	queryParamName           string
	keys                     []string
	removeHeadersOnSuccess   bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v, ctx: %+v\n", name, *config, ctx)

	// check for empty keys
	if len(config.Keys) == 0 {
		return nil, fmt.Errorf("must specify at least one valid key")
	}

	// check at least one method is set
	if !config.AuthenticationHeader && !config.BearerHeader && !config.QueryParam {
		return nil, fmt.Errorf("at least one method must be true")
	}

	return &KeyAuth{
		next:                     next,
		authenticationHeader:     config.AuthenticationHeader,
		authenticationHeaderName: config.AuthenticationHeaderName,
		bearerHeader:             config.BearerHeader,
		bearerHeaderName:         config.BearerHeaderName,
		queryParam:               config.QueryParam,
		queryParamName:           config.QueryParamName,
		keys:                     config.Keys,
		removeHeadersOnSuccess:   config.RemoveHeadersOnSuccess,
	}, nil
}

// contains takes an API key and compares it to the list of valid API keys. The return value notes whether the
// key is in the valid keys
// list or not.
func contains(key string, validKeys []string) bool {
	for _, a := range validKeys {
		if a == key {
			return true
		}
	}
	return false
}

// bearer takes an API key in the `Authorization: Bearer $token` form and compares it to the list of valid keys.
// The token/key is extracted from the header value. The return value notes whether the key is in the valid keys
// list or not.
func bearer(key string, validKeys []string) bool {
	re, _ := regexp.Compile(`Bearer\s(?P<key>[^$]+)`)
	matches := re.FindStringSubmatch(key)

	// If no match found the value is in the wrong form.
	if matches == nil {
		return false
	}

	// If found extract the key and compare it to the list of valid keys
	keyIndex := re.SubexpIndex("key")
	extractedKey := matches[keyIndex]
	return contains(extractedKey, validKeys)
}

func (ka *KeyAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check authentication header for valid key
	if ka.authenticationHeader {
		if contains(req.Header.Get(ka.authenticationHeaderName), ka.keys) {
			// X-API-KEY header contains a valid key
			if ka.removeHeadersOnSuccess {
				req.Header.Del(ka.authenticationHeaderName)
			}
			ka.next.ServeHTTP(rw, req)
			return
		}
	}

	// Check authorization header for valid Bearer
	if ka.bearerHeader {
		if bearer(req.Header.Get(ka.bearerHeaderName), ka.keys) {
			// Authorization header contains a valid Bearer token
			if ka.removeHeadersOnSuccess {
				req.Header.Del(ka.bearerHeaderName)
			}
			ka.next.ServeHTTP(rw, req)
			return
		}
	}

	// Check query param for valid key
	if ka.queryParam {
		var qs = req.URL.Query()
		if contains(qs.Get(ka.queryParamName), ka.keys) {
			qs.Del(ka.queryParamName)
			req.URL.RawQuery = qs.Encode()
			ka.next.ServeHTTP(rw, req)
			return
		}
	}

	var response = Response{
		Message:    "Invalid or missing API Key",
		StatusCode: http.StatusForbidden,
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(response.StatusCode)

	// If no headers or invalid key, return 403
	if err := json.NewEncoder(rw).Encode(response); err != nil {
		// If response cannot be written, log error
		fmt.Printf("Error when sending response to an invalid key: %s", err.Error())
	}
}
