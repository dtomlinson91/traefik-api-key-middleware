package traefik_api_key_middleware

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// regex compilation is pretty expensive, so using a global variable for that seems acceptable
var regKey = regexp.MustCompile(`Bearer\s(?P<key>[^$]+)`)

const (
	bcryptPrefix = "$2y$05$"
	sha1Prefix   = "{SHA}"
)

type Config struct {
	AuthenticationHeader     bool     `json:"authenticationHeader,omitempty"`
	AuthenticationHeaderName string   `json:"headerName,omitempty"`
	BearerHeader             bool     `json:"bearerHeader,omitempty"`
	BearerHeaderName         string   `json:"bearerHeaderName,omitempty"`
	Keys                     []string `json:"keys,omitempty"`
	HashedKeys               []string `json:"hashedKeys,omitempty"`
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
		Keys:                     make([]string, 0),
		HashedKeys:               make([]string, 0),
		RemoveHeadersOnSuccess:   true,
	}
}

type KeyAuth struct {
	next                     http.Handler
	cachedKeys               map[string]struct{}
	cachedKeysMutex          sync.RWMutex
	authenticationHeader     bool
	authenticationHeaderName string
	bearerHeader             bool
	bearerHeaderName         string
	keys                     []string
	sha1HaskedKeys           []string
	bcryptHashedKeys         []string
	removeHeadersOnSuccess   bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v, ctx: %+v\n", name, *config, ctx)

	// check for empty keys
	if len(config.Keys) == 0 {
		return nil, fmt.Errorf("must specify at least one valid key")
	}

	// check at least one header is set
	if !config.AuthenticationHeader && !config.BearerHeader {
		return nil, fmt.Errorf("at least one header type must be true")
	}

	bcryptHashedKeys, sha1HaskedKeys := sortHashedKey(config.HashedKeys)
	cachedKeys := map[string]struct{}{}
	return &KeyAuth{
		next:                     next,
		authenticationHeader:     config.AuthenticationHeader,
		authenticationHeaderName: config.AuthenticationHeaderName,
		bearerHeader:             config.BearerHeader,
		bearerHeaderName:         config.BearerHeaderName,
		keys:                     config.Keys,
		bcryptHashedKeys:         bcryptHashedKeys,
		sha1HaskedKeys:           sha1HaskedKeys,
		removeHeadersOnSuccess:   config.RemoveHeadersOnSuccess,
		cachedKeys:               cachedKeys,
	}, nil
}

func sortHashedKey(hashedKeys []string) ([]string, []string) {
	sha1HaskedKeys := []string{}
	bcryptHashedKeys := []string{}

	for _, key := range hashedKeys {
		switch {
		case strings.HasPrefix(key, bcryptPrefix):
			bcryptHashedKeys = append(bcryptHashedKeys, key)
		case strings.HasPrefix(key, sha1Prefix):
			sha1HaskedKeys = append(sha1HaskedKeys, key)
		default:
		}
	}
	return bcryptHashedKeys, sha1HaskedKeys
}

// extract the API from the classic bearer auth in `Authorization: Bearer $token` form.
func parseKeyFromBearer(key string) (string, error) {
	matches := regKey.FindStringSubmatch(key)
	// If no match found the value is in the wrong form.
	if matches == nil {
		return "", fmt.Errorf("could not parse key from bearer header")
	}
	// If found return extract key
	keyIndex := regKey.SubexpIndex("key")

	return matches[keyIndex], nil
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

func checkSHA1(key string, validHashedKeys []string) bool {
	if len(validHashedKeys) == 0 {
		return false
	}
	sha1Key := sha1.Sum([]byte(key))
	hashedKey := "{SHA}" + base64.StdEncoding.EncodeToString(sha1Key[:])
	return contains(hashedKey, validHashedKeys)
}

func checkBcrypt(key string, validHashedKeys []string) bool {
	result := make(chan bool)

	for _, vk := range validHashedKeys {
		go func(vk string) {
			if err := bcrypt.CompareHashAndPassword([]byte(vk), []byte(key)); err == nil {
				result <- true
			}
			result <- false
		}(vk)
	}

	for i := 0; i < len(validHashedKeys); i++ {
		if <-result {
			return true
		}
	}
	return false
}

func (ka *KeyAuth) containsHash(key string) bool {

	ka.cachedKeysMutex.RLock()
	if _, ok := ka.cachedKeys[key]; ok {
		return true
	}
	ka.cachedKeysMutex.RUnlock()

	result := make(chan bool)

	go func() {
		result <- checkSHA1(key, ka.sha1HaskedKeys)
	}()
	go func() {
		result <- checkBcrypt(key, ka.bcryptHashedKeys)
	}()

	for i := 0; i < 2; i++ {
		if <-result {
			ka.cachedKeysMutex.Lock()
			ka.cachedKeys[key] = struct{}{}
			ka.cachedKeysMutex.Unlock()
			return true
		}
	}
	return false
}

func (ka *KeyAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check authentication header for valid key
	if ka.authenticationHeader {
		key := req.Header.Get(ka.authenticationHeaderName)
		if contains(key, ka.keys) || ka.containsHash(key) {
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
		extractedKey, err := parseKeyFromBearer(req.Header.Get(ka.bearerHeaderName))
		// if we could not extract the key, we continue to return an error
		// checking against plain text keys is super fast, we do that first
		if err == nil && (contains(extractedKey, ka.keys) || ka.containsHash(extractedKey)) {
			// Authorization header contains a valid Bearer token
			if ka.removeHeadersOnSuccess {
				req.Header.Del(ka.bearerHeaderName)
			}
			ka.next.ServeHTTP(rw, req)
			return
		}
	}

	var response Response
	if ka.authenticationHeader && ka.bearerHeader {
		response = Response{
			Message:    fmt.Sprintf("Invalid API Key. Must pass a valid API Key header using either %s: $key or %s: Bearer $key", ka.authenticationHeaderName, ka.bearerHeaderName),
			StatusCode: http.StatusForbidden,
		}
	} else if ka.authenticationHeader && !ka.bearerHeader {
		response = Response{
			Message:    fmt.Sprintf("Invalid API Key. Must pass a valid API Key header using %s: $key", ka.authenticationHeaderName),
			StatusCode: http.StatusForbidden,
		}
	} else if !ka.authenticationHeader && ka.bearerHeader {
		response = Response{
			Message:    fmt.Sprintf("Invalid API Key. Must pass a valid API Key header using %s: Bearer $key", ka.bearerHeaderName),
			StatusCode: http.StatusForbidden,
		}
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(response.StatusCode)

	// If no headers or invalid key, return 403
	if err := json.NewEncoder(rw).Encode(response); err != nil {
		// If response cannot be written, log error
		fmt.Printf("Error when sending response to an invalid key: %s", err.Error())
	}
}
