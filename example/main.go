package main

import (
	"fmt"
	"log"
	"time"

	"github.com/na4ma4/jwt/v2"
)

// Generate Token from authentication service.
//
//nolint:forbidigo // Example
func main() {
	// Create signer using RSA private key in PEM format (no passphrase)
	signer, err := jwt.NewRSASignerFromFile("key.pem")
	if err != nil {
		log.Panic(err)
	}

	// Sign list of claims as a token
	token, err := signer.SignClaims(
		jwt.String(jwt.Subject, "user100"),
		jwt.String(jwt.Audience, "myservice"),
		jwt.Time(jwt.Issued, time.Now()),
		jwt.Time(jwt.NotBefore, time.Now()),
		jwt.Time(jwt.Expires, time.Now().Add(time.Hour)),
	)
	if err != nil {
		log.Panic(err)
	}

	// Give token to client
	fmt.Printf("Token: %s\n", token)

	//
	// Verify on remote service using only the public certificate.
	//

	// Create verifier using certificate in PEM format
	verifier, err := jwt.NewRSAVerifierFromFile([]string{"myservice"}, "cert.pem")
	if err != nil {
		log.Panic(err)
	}

	// Verify token has a valid signature and the audience matches this service
	result, err := verifier.Verify(token)
	if err != nil {
		log.Panic(err)
	}

	// Result contains Subject(username), Audience and other useful data, but just
	// verifier.Verify not throwing an error is enough for validity.
	fmt.Printf("Username: %s\n", result.Subject)
	fmt.Printf("Service: %q\n", result.Audience)
}
