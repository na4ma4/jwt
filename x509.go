package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/spf13/afero"
)

// ErrExtractPublicKey is returned if the public key failed to get extracted from a valid certificate file.
var ErrExtractPublicKey = errors.New("unable to extract public key")

// ParsePKCS1PublicKeyFromFile parses a PKCS1 Public Certificate from a PEM file.
func ParsePKCS1PublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	return ParsePKCS1PublicKeyFromFileAFS(afero.NewOsFs(), filename)
}

// ParsePKCS1PublicKeyFromFileAFS parses a PKCS1 Public Certificate from a PEM file with a supplied `afero.Fs`.
func ParsePKCS1PublicKeyFromFileAFS(afs afero.Fs, filename string) (*rsa.PublicKey, error) {
	data, err := afero.ReadFile(afs, filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read certificate: %w", err)
	}

	return ParsePKCS1PublicKey(data)
}

// ParsePKCS1PublicKey parses a PKCS1 Public Certificate from a byte slice containing a PEM certificate.
func ParsePKCS1PublicKey(data []byte) (*rsa.PublicKey, error) {
	publicPem, _ := pem.Decode(data)

	publicCert, err := x509.ParseCertificate(publicPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %w", err)
	}

	publicKey, ok := publicCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return publicKey, ErrExtractPublicKey
	}

	return publicKey, nil
}

// ParsePKCS1PrivateKeyFromFile parses a PKCS1 Private Key from a PEM file.
func ParsePKCS1PrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	return ParsePKCS1PrivateKeyFromFileAFS(afero.NewOsFs(), filename)
}

// ParsePKCS1PrivateKeyFromFileAFS parses a PKCS1 Private Key from a PEM file with a supplied `afero.Fs`.
func ParsePKCS1PrivateKeyFromFileAFS(afs afero.Fs, filename string) (*rsa.PrivateKey, error) {
	data, err := afero.ReadFile(afs, filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %w", err)
	}

	return ParsePKCS1PrivateKey(data)
}

// ParsePKCS1PrivateKey parses a PKCS1 Private Key from a byte slice containing an RSA key in PEM format.
func ParsePKCS1PrivateKey(data []byte) (*rsa.PrivateKey, error) {
	privatePem, _ := pem.Decode(data)

	privateKey, err := x509.ParsePKCS1PrivateKey(privatePem.Bytes)
	if err != nil {
		return privateKey, fmt.Errorf("unable to parse private key: %w", err)
	}

	return privateKey, nil
}
