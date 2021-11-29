package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"os"
)

const (
	caFilename   = "ca.crt"
	certFilename = "cert.crt"
	keyFilename  = "cert.key"
)

var ca *x509.Certificate
var certificate *x509.Certificate
var privateKey *rsa.PrivateKey

// EnsureKeyMaterial checks if the CA and a local certificate/key
// is available. If not, the CA and/or the certificate are fetched
// from the configured (WirePact-)PKI.
func EnsureKeyMaterial(config *Config) error {
	err := loadCA(config)
	if err != nil {
		return err
	}

	err = loadLocalKey(config)
	if err != nil {
		return err
	}

	err = loadLocalCert(config)
	if err != nil {
		return err
	}

	return nil
}

// GetPrivateKey returns the RSA private key to sign JWTs.
func GetPrivateKey() *rsa.PrivateKey {
	return privateKey
}

// GetJWTCertificateHeaders returns a tuple containing the x5c and x5t
// headers for JWTs. The x5c contains the signing certificate
// with the CA certificate and the x5t header contains a sha 256
// hash of the signing certificate.
//
// Example:
// 	x5c, x5t := pki.GetJWTCertificateHeaders()
// 	jwt.Headers["x5c"] = x5c
// 	jwt.Headers["x5t"] = x5t
func GetJWTCertificateHeaders() ([]string, string) {
	signature := sha256.Sum256(certificate.Raw)
	return []string{
			base64.StdEncoding.EncodeToString(certificate.Raw),
			base64.StdEncoding.EncodeToString(ca.Raw),
		},
		base64.StdEncoding.EncodeToString(signature[:])
}

// GetCA returns the fetched PKI CA certificate.
func GetCA() *x509.Certificate {
	return ca
}

func loadCA(config *Config) error {
	if !config.fileExists(caFilename) {
		response, err := http.Get(config.caAddress())
		if err != nil {
			return err
		}

		caFile, err := os.Create(config.filePath(caFilename))
		if err != nil {
			return err
		}

		_, err = caFile.ReadFrom(response.Body)
		if err != nil {
			return err
		}
		err = caFile.Close()
		if err != nil {
			return err
		}
		err = response.Body.Close()
		if err != nil {
			return err
		}
	}

	certPEMBlock, err := os.ReadFile(config.filePath(caFilename))
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certPEMBlock)

	ca, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	return nil
}

func loadLocalKey(config *Config) error {
	if !config.fileExists(keyFilename) {
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

		keyFile, err := os.Create(config.filePath(keyFilename))
		if err != nil {
			return err
		}
		_, err = keyFile.Write(keyOut)
		if err != nil {
			return err
		}
		err = keyFile.Close()
		if err != nil {
			return err
		}
	} else {
		keyPEMBlock, err := os.ReadFile(config.filePath(keyFilename))
		if err != nil {
			return err
		}

		keyBlock, _ := pem.Decode(keyPEMBlock)
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
	}

	return nil
}

func loadLocalCert(config *Config) error {
	if !config.fileExists(certFilename) {
		csr := x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"WirePact PKI", "Translator"},
				CommonName:   config.CertificateCommonName,
			},
			SignatureAlgorithm: x509.SHA256WithRSA,
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, privateKey)
		if err != nil {
			return err
		}

		csrBuffer := &bytes.Buffer{}
		err = pem.Encode(csrBuffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
		if err != nil {
			return err
		}

		response, err := http.Post(config.csrAddress(), "application/pkcs10", csrBuffer)
		if err != nil {
			return err
		}

		certFile, err := os.Create(config.filePath(certFilename))
		if err != nil {
			return err
		}

		_, err = certFile.ReadFrom(response.Body)
		if err != nil {
			return err
		}
		err = certFile.Close()
		if err != nil {
			return err
		}
		err = response.Body.Close()
		if err != nil {
			return err
		}
	}

	certPEMBlock, err := os.ReadFile(config.filePath(certFilename))
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certPEMBlock)
	certificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	return nil
}
