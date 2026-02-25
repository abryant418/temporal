package auth

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
)

// CipherSuitesFromNames converts a list of cipher suite name strings to their
// corresponding uint16 IDs as used by Go's crypto/tls package. Returns an error
// if any name is unrecognized. Only applies to TLS 1.0–1.2; TLS 1.3 suites
// are not configurable in Go.
func CipherSuitesFromNames(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}

	lookup := make(map[string]uint16)
	for _, cs := range tls.CipherSuites() {
		lookup[cs.Name] = cs.ID
	}
	for _, cs := range tls.InsecureCipherSuites() {
		lookup[cs.Name] = cs.ID
	}

	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, ok := lookup[name]
		if !ok {
			return nil, fmt.Errorf("unrecognized cipher suite: %q", name)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// CipherSuitesFromConfig resolves cipher suite IDs from a config list.
// If the config list is empty, it falls back to the GRPC_SSL_CIPHER_SUITES
// environment variable (colon-separated). If both are empty, returns nil
// (meaning Go defaults will be used).
func CipherSuitesFromConfig(configuredSuites []string) ([]uint16, error) {
	if len(configuredSuites) > 0 {
		return CipherSuitesFromNames(configuredSuites)
	}

	envVal := os.Getenv("GRPC_SSL_CIPHER_SUITES")
	if envVal == "" {
		return nil, nil
	}

	names := strings.Split(envVal, ":")
	return CipherSuitesFromNames(names)
}