package encryption

import (
	"crypto/tls"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCipherSuiteNameToID(t *testing.T) {
	tests := []struct {
		name      string
		expected  uint16
		expectErr bool
	}{
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, false},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, false},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, false},
		// OpenSSL style names
		{"ECDHE-RSA-AES128-GCM-SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, false},
		{"ECDHE-RSA-AES256-GCM-SHA384", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, false},
		{"ECDHE-RSA-CHACHA20-POLY1305", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, false},
		// Unknown cipher suite
		{"UNKNOWN_CIPHER_SUITE", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := CipherSuiteNameToID(tt.name)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, id)
		})
	}
}

func TestCipherSuiteNamesToIDs(t *testing.T) {
	t.Run("empty input returns nil", func(t *testing.T) {
		ids, err := CipherSuiteNamesToIDs(nil)
		require.NoError(t, err)
		require.Nil(t, ids)

		ids, err = CipherSuiteNamesToIDs([]string{})
		require.NoError(t, err)
		require.Nil(t, ids)
	})

	t.Run("valid cipher suites", func(t *testing.T) {
		names := []string{
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		}
		ids, err := CipherSuiteNamesToIDs(names)
		require.NoError(t, err)
		require.Len(t, ids, 2)
		require.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ids[0])
		require.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ids[1])
	})

	t.Run("TLS 1.3 cipher suites are skipped", func(t *testing.T) {
		names := []string{
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		}
		ids, err := CipherSuiteNamesToIDs(names)
		require.NoError(t, err)
		require.Len(t, ids, 1)
		require.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ids[0])
	})

	t.Run("unknown cipher suite returns error", func(t *testing.T) {
		names := []string{
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"UNKNOWN_CIPHER",
		}
		_, err := CipherSuiteNamesToIDs(names)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown cipher suite")
	})
}

func TestResolveCipherSuites(t *testing.T) {
	t.Run("config takes precedence over env", func(t *testing.T) {
		t.Setenv("GRPC_SSL_CIPHER_SUITES", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
		configSuites := []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
		ids, err := ResolveCipherSuites(configSuites)
		require.NoError(t, err)
		require.Len(t, ids, 1)
		require.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ids[0])
	})

	t.Run("env var used when config is empty", func(t *testing.T) {
		t.Setenv("GRPC_SSL_CIPHER_SUITES", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
		ids, err := ResolveCipherSuites(nil)
		require.NoError(t, err)
		require.Len(t, ids, 2)
	})

	t.Run("returns nil when no config and no env", func(t *testing.T) {
		// Ensure env var is not set
		os.Unsetenv("GRPC_SSL_CIPHER_SUITES")
		ids, err := ResolveCipherSuites(nil)
		require.NoError(t, err)
		require.Nil(t, ids)
	})

	t.Run("env var with colon-separated list", func(t *testing.T) {
		t.Setenv("GRPC_SSL_CIPHER_SUITES", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305")
		ids, err := ResolveCipherSuites(nil)
		require.NoError(t, err)
		require.Len(t, ids, 3)
		require.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ids[0])
		require.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ids[1])
		require.Equal(t, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, ids[2])
	})
}