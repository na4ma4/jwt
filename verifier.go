package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	pascaljwt "github.com/pascaldekloe/jwt"
)

// ErrTokenInvalidAudience is the error returned when an audience does not match the token.
var ErrTokenInvalidAudience = errors.New("invalid token audience")

// ErrTokenTimeNotValid is the general error returned when a token is outside the NotBefore or Expires times.
var ErrTokenTimeNotValid = errors.New("token time is not valid")

// VerifyResult returns the information about the token verification.
type VerifyResult struct {
	ID             string
	IsOnline       bool
	Subject        string
	Audience       AudienceSlice
	ClaimAudiences AudienceSlice
	Fingerprint    string
	NotBefore      time.Time
	Expires        time.Time
	Claims         map[string]Claim
}

// Verifier takes a token and returns the subject if it is valid, or an error if it is not.
type Verifier interface {
	// Verify processes a supplied token
	Verify(token []byte) (VerifyResult, error)
}

// RSAVerifier implements the `Verifier` interface and tests a token signed with RSA public/private keys.
type RSAVerifier struct {
	PublicKey *rsa.PublicKey
	Issuer    string
	Audiences []string
	// Algorithms []string
}

// NewRSAVerifierFromFile returns an `RSAVerifier` initialized with the RSA Public Key
// supplied and an audience for token verification.
func NewRSAVerifierFromFile(audiences []string, filename string) (Verifier, error) {
	publicKey, err := ParsePKCS1PublicKeyFromFile(filename)
	if err != nil {
		return nil, err
	}

	return &RSAVerifier{
		Audiences: audiences,
		PublicKey: publicKey,
		// Algorithms: []string{pascaljwt.RS256, pascaljwt.RS384, pascaljwt.RS512},
	}, nil
}

func (v *RSAVerifier) getClaimMapFromClaims(claims *pascaljwt.Claims) (map[string]Claim, error) {
	c := make(map[string]Claim)

	if claims.Subject != "" {
		c[Subject] = String(Subject, claims.Subject)
	}

	if claims.NotBefore != nil {
		c[NotBefore] = Time(NotBefore, claims.NotBefore.Time())
	}

	if claims.Expires != nil {
		c[Expires] = Time(Expires, claims.Expires.Time())
	}

	if claims.Audiences != nil {
		c[Audience] = Strings(Audience, claims.Audiences)
	}

	for k, v := range claims.Set {
		switch k {
		case NotBefore, Expires, Issued:
			if f, ok := claims.Number(k); ok {
				t := time.Unix(0, int64(f*float64(time.Second)))
				c[k] = Time(k, t)
			} else {
				return c, ErrInvalidClaimType
			}
		default:
			c[k] = Any(k, v)
		}
	}

	return c, nil
}

// Verify takes the token and checks it's signature against the RSA public key,
// and the audience, notbefore and expires validity.
func (v *RSAVerifier) Verify(token []byte) (VerifyResult, error) {
	checkTime := time.Now()
	result := VerifyResult{}

	claims, err := pascaljwt.RSACheck(token, v.PublicKey)
	if err != nil {
		return result, fmt.Errorf("jwt failed check: %w", err)
	}

	if !v.hasAudience(claims.Audiences) {
		return result, ErrTokenInvalidAudience
	}

	acceptedAudiences := v.matchingAudiences(claims.Audiences)

	if !claims.Valid(checkTime) {
		return result, ErrTokenTimeNotValid
	}

	online := false
	if val, ok := claims.Set["onl"]; ok {
		online, _ = val.(bool)
	}

	fingerprint := ""
	if val, ok := claims.Set["fpt"]; ok {
		fingerprint, _ = val.(string)
	}

	result = VerifyResult{
		Subject:        claims.Subject,
		IsOnline:       online,
		ID:             claims.ID,
		Audience:       acceptedAudiences,
		ClaimAudiences: claims.Audiences,
		Fingerprint:    fingerprint,
		NotBefore:      time.Time{},
		Expires:        time.Time{},
	}

	if claims.NotBefore != nil {
		result.NotBefore = claims.NotBefore.Time()
	}

	if claims.Expires != nil {
		result.Expires = claims.Expires.Time()
	}

	result.Claims, err = v.getClaimMapFromClaims(claims)
	// result.Claims[Audience] = String(Audience, v.Audiences)

	return result, err
}

func (v *RSAVerifier) matchingAudiences(claimAudiences []string) []string {
	o := []string{}

	for _, v := range v.Audiences {
		for _, c := range claimAudiences {
			if strings.EqualFold(v, c) {
				o = append(o, c)
			}
		}
	}

	return o
}

func (v *RSAVerifier) hasAudience(claimAudiences AudienceSlice) bool {
	return claimAudiences.HasAny(v.Audiences)
}
