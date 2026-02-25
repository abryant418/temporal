package encryption

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
)

// cipherSuiteNameToID maps cipher suite names to their uint16 IDs.
// This includes both Go standard names and OpenSSL/IANA names for compatibility.
var cipherSuiteNameToID = map[string]uint16{
	// TLS 1.2 cipher suites (Go standard names)
	"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

	// Alternative names (OpenSSL style) for common cipher suites
	"ECDHE-RSA-AES128-GCM-SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES256-GCM-SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-AES128-GCM-SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES256-GCM-SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-CHACHA20-POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-ECDSA-CHACHA20-POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
}

// CipherSuiteNameToID converts a cipher suite name to its uint16 ID.
// Returns an error if the cipher suite name is not recognized.
func CipherSuiteNameToID(name string) (uint16, error) {
	if id, ok := cipherSuiteNameToID[name]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("unknown cipher suite: %s", name)
}

// CipherSuiteNamesToIDs converts a slice of cipher suite names to their uint16 IDs.
// Returns an error if any cipher suite name is not recognized.
func CipherSuiteNamesToIDs(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		// Skip TLS 1.3 cipher suites as they are not configurable in Go
		if strings.HasPrefix(name, "TLS_AES_") || strings.HasPrefix(name, "TLS_CHACHA20_") {
			continue
		}
		id, err := CipherSuiteNameToID(name)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// ResolveCipherSuites returns cipher suite IDs from config or GRPC_SSL_CIPHER_SUITES env var.
// The config takes precedence over the environment variable.
// Returns nil if no custom suites are configured (use Go defaults).
func ResolveCipherSuites(configSuites []string) ([]uint16, error) {
	suites := configSuites
	if len(suites) == 0 {
		if envSuites := os.Getenv("GRPC_SSL_CIPHER_SUITES"); envSuites != "" {
			suites = strings.Split(envSuites, ":")
		}
	}
	if len(suites) == 0 {
		return nil, nil
	}
	return CipherSuiteNamesToIDs(suites)
}