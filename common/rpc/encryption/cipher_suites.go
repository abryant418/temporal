package encryption

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
)

// GRPCSSLCipherSuitesEnvVar is the environment variable name used as a fallback
// for cipher suite configuration, matching gRPC's standard.
const GRPCSSLCipherSuitesEnvVar = "GRPC_SSL_CIPHER_SUITES"

// cipherSuiteNameToID maps cipher suite names to their uint16 IDs.
// This includes all cipher suites supported by Go's crypto/tls package.
var cipherSuiteNameToID = map[string]uint16{
	// TLS 1.0 - 1.2 cipher suites
	"TLS_RSA_WITH_RC4_128_SHA":                      tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	// Aliases without _SHA256 suffix (commonly used)
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	// OpenSSL/IANA style names (commonly used in GRPC_SSL_CIPHER_SUITES)
	"ECDHE-RSA-AES128-GCM-SHA256":       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES256-GCM-SHA384":       tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-AES128-GCM-SHA256":     tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES256-GCM-SHA384":     tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-CHACHA20-POLY1305":       tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-ECDSA-CHACHA20-POLY1305":     tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-RSA-AES128-SHA256":           tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-RSA-AES128-SHA":              tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-RSA-AES256-SHA":              tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"AES128-GCM-SHA256":                 tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"AES256-GCM-SHA384":                 tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"AES128-SHA256":                     tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"AES128-SHA":                        tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"AES256-SHA":                        tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	// TLS 1.3 cipher suite names (for documentation; Go handles TLS 1.3 suites automatically)
	"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
	"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
}

// ResolveCipherSuites converts a list of cipher suite names to their uint16 IDs.
// If configuredSuites is empty, it falls back to the GRPC_SSL_CIPHER_SUITES environment variable.
// Returns nil if no cipher suites are configured (meaning Go's defaults will be used).
// Returns an error if any cipher suite name is not recognized.
func ResolveCipherSuites(configuredSuites []string) ([]uint16, error) {
	suiteNames := configuredSuites

	// Fall back to environment variable if no suites configured
	if len(suiteNames) == 0 {
		envSuites := os.Getenv(GRPCSSLCipherSuitesEnvVar)
		if envSuites != "" {
			suiteNames = strings.Split(envSuites, ":")
		}
	}

	// If still no suites, return nil (use Go defaults)
	if len(suiteNames) == 0 {
		return nil, nil
	}

	result := make([]uint16, 0, len(suiteNames))
	for _, name := range suiteNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, ok := cipherSuiteNameToID[name]
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite: %q", name)
		}
		result = append(result, id)
	}

	if len(result) == 0 {
		return nil, nil
	}

	return result, nil
}

// GetSupportedCipherSuiteNames returns a list of all supported cipher suite names.
// This can be used for documentation or validation purposes.
func GetSupportedCipherSuiteNames() []string {
	names := make([]string, 0, len(cipherSuiteNameToID))
	for name := range cipherSuiteNameToID {
		names = append(names, name)
	}
	return names
}