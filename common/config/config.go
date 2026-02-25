		// RequireClientAuth specifies whether the server requires client authentication.
		RequireClientAuth bool `yaml:"requireClientAuth"`
		// CipherSuites is an optional list of supported cipher suites for TLS 1.0-1.2.
		// If empty, Go's default cipher suites are used. As a fallback, the GRPC_SSL_CIPHER_SUITES
		// environment variable is also checked (colon-separated list of cipher suite names).
		// Use Go standard names, e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".
		// Note: TLS 1.3 cipher suites are not configurable in Go and are always used when TLS 1.3 is negotiated.
		CipherSuites []string `yaml:"cipherSuites"`