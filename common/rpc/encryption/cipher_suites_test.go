package encryption

import (
	"crypto/tls"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveCipherSuites(t *testing.T) {
	tests := []struct {
		name        string
		suites      []string
		envValue    string
		wantIDs     []uint16
		wantErr     bool
		errContains string
	}{
		{
		name:    "empty config and env returns nil",
		suites:  nil,
		wantIDs: nil,
		},
		{
		name:    "Go standard names",
		suites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		wantIDs: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		{
		name:    "OpenSSL style names",
		suites:  []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"},
		wantIDs: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		{
		name:    "mixed naming styles",
		suites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES256-GCM-SHA384"},
		wantIDs: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		{
		name:     "falls back to env var",
		suites:   nil,
		envValue: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		wantIDs:  []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		{
		name:     "config takes precedence over env",
		suites:   []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		envValue: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		wantIDs:  []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		},
		{
		name:        "unknown cipher suite returns error",
		suites:      []string{"UNKNOWN_CIPHER_SUITE"},
		wantErr:     true,
		errContains: "unknown cipher suite",
		},
		{
		name:    "empty strings are skipped",
		suites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "", "  "},
		wantIDs: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		{
		name:    "whitespace is trimmed",
		suites:  []string{"  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  "},
		wantIDs: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		{
		name:    "ChaCha20 suites",
		suites:  []string{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305"},
		wantIDs: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		},
		{
		name:    "TLS 1.3 suite names",
		suites:  []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		wantIDs: []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				t.Setenv(GRPCSSLCipherSuitesEnvVar, tc.envValue)
			} else {
				// Clear env var if not set for this test
				os.Unsetenv(GRPCSSLCipherSuitesEnvVar)
			}

			got, err := ResolveCipherSuites(tc.suites)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					require.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantIDs, got)
		})
	}
}

func TestGetSupportedCipherSuiteNames(t *testing.T) {
	names := GetSupportedCipherSuiteNames()
	require.NotEmpty(t, names)

	// Verify some expected names are present
	nameSet := make(map[string]bool)
	for _, name := range names {
		nameSet[name] = true
	}
	require.True(t, nameSet["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"])
	require.True(t, nameSet["ECDHE-RSA-AES128-GCM-SHA256"])
}