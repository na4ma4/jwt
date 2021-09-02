package jwt

import (
	"crypto/rsa"
	"fmt"

	pascaljwt "github.com/pascaldekloe/jwt"
)

// DockerDistributionRSASigner implements the `Signer` interface and creates a token signed with RSA public/private keys that returns tokens
// that will work with docker/distribution.
type DockerDistributionRSASigner struct {
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Algorithm  string
}

// NewDockerDistributionRSASignerFromFile returns an `DockerDistributionRSASigner` initialized with the RSA Private Key supplied.
func NewDockerDistributionRSASignerFromFile(filename string) (Signer, error) {
	privateKey, err := ParsePKCS1PrivateKeyFromFile(filename)
	if err != nil {
		return nil, err
	}

	return &DockerDistributionRSASigner{
		PrivateKey: privateKey,
		Algorithm:  pascaljwt.RS256,
	}, nil
}

// SignClaims takes a list of claims and produces a signed token.
func (r *DockerDistributionRSASigner) SignClaims(claims ...Claim) ([]byte, error) {
	tokenClaims, err := ConstructClaimsFromSlice(
		append(
			[]Claim{String("iss", r.Issuer)},
			claims...,
		)...,
	)
	if err != nil {
		return nil, err
	}

	for i := range claims {
		if claims[i].Key == Audience {
			if v, ok := claims[i].Interface.([]string); ok && len(v) > 0 {
				claims[i].String = v[0]
				claims[i].Type = StringType
			}
		}
	}

	token, err := tokenClaims.RSASign(r.Algorithm, r.PrivateKey)
	if err != nil {
		return token, fmt.Errorf("unable to sign claims: %w", err)
	}

	return token, nil
}
