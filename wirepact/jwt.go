package wirepact

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"time"

	"github.com/WirePact/go-translator/pki"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// CreateSignedJWTForUser creates a valid signed JWT for the given userID.
// The JWT is signed with the private key (RSA256) from the key material.
// Additionally, the optional headers "x5c" and "x5t"
// (https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6)
// are added - as they are required by WirePact - to enable the receiver to validate
// the presented signature. The audience is always set to "WirePact".
func CreateSignedJWTForUser(config *JWTConfig, userID string) (string, error) {
	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       pki.GetPrivateKey(),
	}

	x5c, x5t := pki.GetJWTCertificateHeaders()

	var signerOpts = jose.SignerOptions{}
	signerOpts.
		WithType("JWT").
		WithHeader("x5c", x5c).
		WithHeader("x5t", x5t)

	rsaSigner, err := jose.NewSigner(signingKey, &signerOpts)
	if err != nil {
		return "", err
	}

	builder := jwt.Signed(rsaSigner)

	lifetime := config.Lifetime
	if lifetime == 0 {
		lifetime = 60 * time.Second
	}

	if config.Issuer == "" {
		return "", errors.New("empty issuer")
	}

	claims := &jwt.Claims{
		Subject:  userID,
		Issuer:   config.Issuer,
		Audience: jwt.Audience{"WirePact"},
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(lifetime)),
	}

	signedToken, err := builder.Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// GetJWTUserSubject takes the WirePact encoded JWT and extracts the user subject.
// First, the function checks the x5c and x5t headers and validates the
// JWT signature against its own CA certificate. Then, if the JWT is valid
// the subject is extracted. If any error occurs (missing certificate headers,
// wrong certificate or other errors) the error is returned with an empty string.
func GetJWTUserSubject(wirePactJWT string) (string, error) {
	parsedJWT, err := jwt.ParseSigned(wirePactJWT)
	if err != nil {
		return "", err
	}

	if len(parsedJWT.Headers) < 1 {
		return "", errors.New("missing jwt headers")
	}

	header := parsedJWT.Headers[0]

	roots := x509.NewCertPool()
	roots.AddCert(pki.GetCA())

	certificateChain, err := header.Certificates(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		return "", err
	}

	signerCertificateHash, ok := header.ExtraHeaders["x5t"]
	if !ok {
		return "", errors.New("x5t signer hash missing")
	}

	signerCertificate := certificateChain[0][0]

	calculatedSignerHash := sha256.Sum256(signerCertificate.Raw)
	calculatedSignerHashString := base64.StdEncoding.EncodeToString(calculatedSignerHash[:])

	if calculatedSignerHashString != signerCertificateHash {
		return "", errors.New("transported hash (x5t) does not match signer certificate hash")
	}

	claims := &jwt.Claims{}
	err = parsedJWT.UnsafeClaimsWithoutVerification(claims)
	if err != nil {
		return "", err
	}

	return claims.Subject, nil
}
