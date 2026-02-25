package encryption

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
)

// GRPCSSLCipherSuitesEnvVar is the environment variable that gRPC-Go checks
// for a colon-separated list of cipher suite names.
const GRPCSSLCipherSuitesEnvVar = "GRPC_SSL_CIPHER_SUITES"

// openSSLToGo maps OpenSSL-style cipher suite names to Go standard names.
var openSSLToGo = map[string]string{
	// TLS 1.2 ECDHE RSA suites
	"ECDHE-RSA-AES128-GCM-SHA256":       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384":       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"ECDHE-RSA-AES128-SHA256":           "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"ECDHE-RSA-AES128-SHA":              "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"ECDHE-RSA-AES256-SHA":              "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	"ECDHE-RSA-CHACHA20-POLY1305":       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	// TLS 1.2 ECDHE ECDSA suites
	"ECDHE-ECDSA-AES128-GCM-SHA256":     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384":     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"ECDHE-ECDSA-AES128-SHA256":         "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"ECDHE-ECDSA-AES128-SHA":            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"ECDHE-ECDSA-AES256-SHA":            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	"ECDHE-ECDSA-CHACHA20-POLY1305":     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	// TLS 1.2 RSA suites
	"AES128-GCM-SHA256":                 "TLS_RSA_WITH_AES_128_GCM_SHA256",
	"AES256-GCM-SHA384":                 "TLS_RSA_WITH_AES_256_GCM_SHA384",
	"AES128-SHA256":                     "TLS_RSA_WITH_AES_128_CBC_SHA256",
	"AES128-SHA":                        "TLS_RSA_WITH_AES_128_CBC_SHA",
	"AES256-SHA":                        "TLS_RSA_WITH_AES_256_CBC_SHA",
	// TLS 1.3 suites (OpenSSL style)
	"TLS_AES_128_GCM_SHA256":            "TLS_AES_128_GCM_SHA256",
	"TLS_AES_256_GCM_SHA384":            "TLS_AES_256_GCM_SHA384",
	"TLS_CHACHA20_POLY1305_SHA256":      "TLS_CHACHA20_POLY1305_SHA256",
}

// goNameToID maps Go standard cipher suite names to their IDs.
var goNameToID map[string]uint16

func init() {
	goNameToID = make(map[string]uint16)
	for _, suite := range tls.CipherSuites() {
		goNameToID[suite.Name] = suite.ID
	}
	for _, suite := range tls.InsecureCipherSuites() {
		goNameToID[suite.Name] = suite.ID
	}
}

// ResolveCipherSuites converts cipher suite names (Go standard or OpenSSL style)
// to their corresponding TLS cipher suite IDs.
// If configSuites is empty, it falls back to the GRPC_SSL_CIPHER_SUITES environment variable.
// Returns nil if no cipher suites are configured (uses Go defaults).
func ResolveCipherSuites(configSuites []string) ([]uint16, error) {
	suites := configSuites
	if len(suites) == 0 {
		if env := os.Getenv(GRPCSSLCipherSuitesEnvVar); env != "" {
			suites = strings.Split(env, ":")
		}
	}

	if len(suites) == 0 {
		return nil, nil
	}

	var ids []uint16
	for _, name := range suites {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		id, err := cipherSuiteNameToID(name)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	return ids, nil
}

// cipherSuiteNameToID converts a cipher suite name to its ID.
// It accepts both Go standard names and OpenSSL-style names.
func cipherSuiteNameToID(name string) (uint16, error) {
	// Try Go standard name first
	if id, ok := goNameToID[name]; ok {
		return id, nil
	}

	// Try OpenSSL-style name
	if goName, ok := openSSLToGo[name]; ok {
		if id, ok := goNameToID[goName]; ok {
			return id, nil
		}
	}

	return 0, fmt.Errorf("unknown cipher suite: %q", name)
}

// GetSupportedCipherSuiteNames returns a list of all supported cipher suite names,
// including both Go standard names and OpenSSL-style aliases.
func GetSupportedCipherSuiteNames() []string {
	var names []string
	for name := range goNameToID {
		names = append(names, name)
	}
	for name := range openSSLToGo {
		names = append(names, name)
	}
	return names
}