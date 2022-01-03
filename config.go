package go_translator

import (
	"errors"
	"os"
	"strconv"

	"github.com/WirePact/go-translator/pki"
	"github.com/WirePact/go-translator/translator"
	"github.com/WirePact/go-translator/wirepact"
	"github.com/sirupsen/logrus"
)

const (
	TranslatorEnvPkiAddress      = "PKI_ADDRESS"
	TranslatorEnvIngressPort     = "INGRESS_PORT"
	TranslatorEnvEgressPort      = "EGRESS_PORT"
	TranslatorEnvCommonName      = "COMMON_NAME"
	TranslatorDefaultIngressPort = 50051
	TranslatorDefaultEgressPort  = 50052
	TranslatorDefaultCaPath      = "/ca"
	TranslatorDefaultCsrPath     = "/csr"
)

// TranslatorConfig contains all necessary configurations for the Translator.
type TranslatorConfig struct {
	// Port for the incoming communication grpc server.
	IngressPort int
	// Function for the incoming translation.
	IngressTranslator translator.IngressTranslation

	// Port for the outgoing communication grpc server.
	EgressPort int
	// Function for the outgoing translation.
	EgressTranslator translator.EgressTranslation

	// Config for the PKI.
	pki.Config
	// Config for the WirePact JWT.
	wirepact.JWTConfig
}

// NewConfigFromEnvironmentVariables returns a TranslatorConfig that is filled
// with values from environment variables. The config can further be customized
// after it is returned.
//
// The variables are:
// INGRESS_PORT, EGRESS_PORT, PKI_ADDRESS, COMMON_NAME
// The common name gets set for the certificate common name and the issuer for the JWTs.
// Ingress and Egress ports have default values.
func NewConfigFromEnvironmentVariables(
	ingressTranslator translator.IngressTranslation,
	egressTranslator translator.EgressTranslation) (TranslatorConfig, error) {
	pkiAddress := os.Getenv(TranslatorEnvPkiAddress)
	if pkiAddress == "" {
		logrus.Error("PKI_ADDRESS env variable is not set.")
		return TranslatorConfig{}, errors.New(ErrPkiAddressNotSet)
	}

	commonName := os.Getenv(TranslatorEnvCommonName)
	if commonName == "" {
		logrus.Error("COMMON_NAME env variable is not set.")
		return TranslatorConfig{}, errors.New(ErrCommonNameNotSet)
	}

	ingressPort := getIntEnvironment(TranslatorEnvIngressPort, TranslatorDefaultIngressPort)
	egressPort := getIntEnvironment(TranslatorEnvEgressPort, TranslatorDefaultEgressPort)

	logrus.WithFields(map[string]interface{}{
		"COMMON_NAME":  commonName,
		"PKI_ADDRESS":  pkiAddress,
		"INGERSS_PORT": ingressPort,
		"EGRESS_PORT":  egressPort,
	}).Info("Create translator config.")

	return TranslatorConfig{
		IngressPort:       ingressPort,
		IngressTranslator: ingressTranslator,
		EgressPort:        egressPort,
		EgressTranslator:  egressTranslator,
		Config: pki.Config{
			BaseAddress:           pkiAddress,
			CAPath:                TranslatorDefaultCaPath,
			CSRPath:               TranslatorDefaultCsrPath,
			CertificateCommonName: commonName,
		},
		JWTConfig: wirepact.JWTConfig{
			Issuer: commonName,
		},
	}, nil
}

func getIntEnvironment(name string, defaultValue int) int {
	if value, ok := os.LookupEnv(name); ok {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
