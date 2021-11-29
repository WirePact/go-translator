package pki

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config contains the information about the PKI.
// It instructs the certificate methods on where to fetch
// the CA certificate and where to send the CSR to.
type Config struct {
	// The base address (uri) of the PKI.
	// This config is only compatible with the k8s-pki for WirePact
	// (https://github.com/WirePact/k8s-pki).
	BaseAddress string

	// The path of the CA (http get) endpoint.
	CAPath string

	// The path of the CSR (http post) endpoint.
	CSRPath string

	// If set, defines a relative or absolute path to a directory
	// where the key material should be stored. If omitted, the current
	// application execution directory is used.
	LocalCertPath string

	// The name that should be set in the CSR as the common name for the translator.
	CertificateCommonName string
}

func (config *Config) caAddress() string {
	return fmt.Sprintf("%v%v", config.BaseAddress, config.CAPath)
}

func (config *Config) csrAddress() string {
	return fmt.Sprintf("%v%v", config.BaseAddress, config.CSRPath)
}

func (config *Config) fileExists(filename string) bool {
	_, err := os.Stat(config.filePath(filename))
	return err == nil
}

func (config *Config) filePath(filename string) string {
	if config.LocalCertPath != "" {
		return filepath.Join(config.LocalCertPath, filename)
	}

	return filename
}
