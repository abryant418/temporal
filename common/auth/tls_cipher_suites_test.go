package auth

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCipherSuitesFromNames_ValidNames(t *testing.T) {
	names := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}
	ids, err := CipherSuitesFromNames(names)
	require.NoError(t, err)
	assert.Equal(t, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}, ids)
}

func TestCipherSuitesFromNames_InvalidName(t *testing.T) {
	names := []string{"NOT_A_REAL_CIPHER"}
	ids, err := CipherSuitesFromNames(names)
	assert.Nil(t, ids)
	assert.ErrorContains(t, err, "unrecognized cipher suite")
}

func TestCipherSuitesFromNames_Empty(t *testing.T) {
	ids, err := CipherSuitesFromNames(nil)
	require.NoError(t, err)
	assert.Nil(t, ids)

	ids, err = CipherSuitesFromNames([]string{})
	require.NoError(t, err)
	assert.Nil(t, ids)
}

func TestCipherSuitesFromNames_WhitespaceHandling(t *testing.T) {
	names := []string{"  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  ", ""}
	ids, err := CipherSuitesFromNames(names)
	require.NoError(t, err)
	assert.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, ids)
}

func TestCipherSuitesFromConfig_UsesConfigFirst(t *testing.T) {
	configured := []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	// Even if env is set, config takes priority
	t.Setenv("GRPC_SSL_CIPHER_SUITES", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	ids, err := CipherSuitesFromConfig(configured)
	require.NoError(t, err)
	assert.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, ids)
}

func TestCipherSuitesFromConfig_FallsBackToEnv(t *testing.T) {
	t.Setenv("GRPC_SSL_CIPHER_SUITES",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	ids, err := CipherSuitesFromConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}, ids)
}

func TestCipherSuitesFromConfig_NothingConfigured(t *testing.T) {
	t.Setenv("GRPC_SSL_CIPHER_SUITES", "")
	ids, err := CipherSuitesFromConfig(nil)
	require.NoError(t, err)
	assert.Nil(t, ids)
}