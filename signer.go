package jwt

import (
	"crypto/rsa"
	"fmt"
	"time"

	pascaljwt "github.com/pascaldekloe/jwt"
)

const (
	// RS256 RSASSA-PKCS1-v1_5 with SHA-256.
	RS256 = pascaljwt.RS256
	// RS384 RSASSA-PKCS1-v1_5 with SHA-348.
	RS384 = pascaljwt.RS384
	// RS512 RSASSA-PKCS1-v1_5 with SHA-512.
	RS512 = pascaljwt.RS512
)

// // ErrAlgorithmUnknown signals an unsupported "alg" token (for the respective method).
// var ErrAlgorithmUnknown = pascaljwt.AlgError

// Signer produces a token from a supplied subject and audience with notbefore and expiry times.
type Signer interface {
	SignClaims(claims ...Claim) ([]byte, error)
}

// RSASigner implements the `Signer` interface and creates a token signed with RSA public/private keys.
type RSASigner struct {
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Algorithm  string
}

// NewRSASignerFromFile returns an `RSASigner` initialized with the RSA Private Key supplied.
func NewRSASignerFromFile(filename string) (Signer, error) {
	privateKey, err := ParsePKCS1PrivateKeyFromFile(filename)
	if err != nil {
		return nil, err
	}

	return &RSASigner{
		PrivateKey: privateKey,
		Algorithm:  pascaljwt.RS256,
	}, nil
}

// SignClaims takes a list of claims and produces a signed token.
func (r *RSASigner) SignClaims(claims ...Claim) ([]byte, error) {
	tokenClaims, err := ConstructClaimsFromSlice(
		append(
			[]Claim{String("iss", r.Issuer)},
			claims...,
		)...,
	)
	if err != nil {
		return nil, err
	}

	token, err := tokenClaims.RSASign(r.Algorithm, r.PrivateKey)
	if err != nil {
		return token, fmt.Errorf("unable to sign claims: %w", err)
	}

	return token, nil
}

// Sign takes a signer, subject, audience, online status, notBefore and expiry and produces a signed token.
func Sign(
	signer Signer,
	audience []string,
	subject string,
	online bool,
	notBefore, expiry time.Time,
) ([]byte, error) {
	token, err := signer.SignClaims(
		String(Subject, subject),
		Strings(Audience, audience),
		Bool("onl", online),
		Time(NotBefore, notBefore),
		Time(Expires, expiry),
	)
	if err != nil {
		return token, fmt.Errorf("unable to sign claims: %w", err)
	}

	return token, nil
}
