package encryption

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
)

// grpcSSLCipherSuitesEnv is the environment variable used by gRPC to configure cipher suites
const grpcSSLCipherSuitesEnv = "GRPC_SSL_CIPHER_SUITES"

// tls13CipherSuites are the TLS 1.3 cipher suites that are not configurable in Go
var tls13CipherSuites = map[string]bool{
	"TLS_AES_128_GCM_SHA256":       true,
	"TLS_AES_256_GCM_SHA384":       true,
	"TLS_CHACHA20_POLY1305_SHA256": true,
}

// openSSLToGoNames maps OpenSSL cipher suite names to Go cipher suite names
var openSSLToGoNames = map[string]string{
	"ECDHE-RSA-AES128-GCM-SHA256":       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384":       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"ECDHE-ECDSA-AES128-GCM-SHA256":     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384":     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"ECDHE-RSA-CHACHA20-POLY1305":       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	"ECDHE-ECDSA-CHACHA20-POLY1305":     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	"ECDHE-RSA-AES128-SHA256":           "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"ECDHE-RSA-AES256-SHA384":           "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	"ECDHE-ECDSA-AES128-SHA256":         "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"AES128-GCM-SHA256":                 "TLS_RSA_WITH_AES_128_GCM_SHA256",
	"AES256-GCM-SHA384":                 "TLS_RSA_WITH_AES_256_GCM_SHA384",
	"AES128-SHA256":                     "TLS_RSA_WITH_AES_128_CBC_SHA256",
}

// CipherSuiteNameToID converts a cipher suite name (Go or OpenSSL style) to its uint16 ID.
// Returns an error if the cipher suite name is not recognized.
func CipherSuiteNameToID(name string) (uint16, error) {
	// Try to convert OpenSSL name to Go name first
	if goName, ok := openSSLToGoNames[name]; ok {
		name = goName
	}

	// Check standard cipher suites
	for _, suite := range tls.CipherSuites() {
		if suite.Name == name {
			return suite.ID, nil
		}
	}

	// Check insecure cipher suites (for completeness, though they shouldn't be used)
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.Name == name {
			return suite.ID, nil
		}
	}

	return 0, fmt.Errorf("unknown cipher suite: %s", name)
}

// CipherSuiteNamesToIDs converts a list of cipher suite names to their uint16 IDs.
// TLS 1.3 cipher suites are silently skipped as they cannot be configured in Go.
// Returns an error if any non-TLS-1.3 cipher suite name is not recognized.
func CipherSuiteNamesToIDs(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}

	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		// Skip TLS 1.3 cipher suites (they cannot be configured in Go)
		if tls13CipherSuites[name] {
			continue
		}

		id, err := CipherSuiteNameToID(name)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return nil, nil
	}
	return ids, nil
}

// ResolveCipherSuites resolves cipher suites from config or environment variable.
// If configSuites is non-empty, it takes precedence.
// Otherwise, the GRPC_SSL_CIPHER_SUITES environment variable is checked (colon-separated list).
// Returns nil if no cipher suites are configured (use Go defaults).
func ResolveCipherSuites(configSuites []string) ([]uint16, error) {
	if len(configSuites) > 0 {
		return CipherSuiteNamesToIDs(configSuites)
	}

	// Fall back to environment variable
	envValue := os.Getenv(grpcSSLCipherSuitesEnv)
	if envValue == "" {
		return nil, nil
	}

	names := strings.Split(envValue, ":")
	return CipherSuiteNamesToIDs(names)
}