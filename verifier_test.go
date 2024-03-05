package jwt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/na4ma4/jwt/v2"
)

// notBefore = time.Now().Add(-1 * time.Minute).UTC()
// expiry = time.Now().Add(time.Hour).UTC()

func TestJWTVerifier_ShouldSucceed(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	tests := []struct {
		name, audience, subject string
		online                  bool
		nbf, exp                time.Time
	}{
		{
			"primary audience token",
			"test-audience", "test-subject", false,
			time.Now().Add(-1 * time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		},
		{
			"secondary audience token",
			"second-test-audience", "test-subject", false,
			time.Now().Add(-1 * time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		},
		{
			"standard token",
			"test-audience", "test-subject", false,
			time.Now().Add(-1 * time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		},
		{
			"offline with array of claims",
			"test-audience", "test-subject", false,
			time.Now().Add(-1 * time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		},
		{
			"online with array of claims",
			"test-audience", "test-subject", true,
			time.Now().Add(-1 * time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audiences := jwt.AudienceSlice{tt.audience}
			token, err := jwt.Sign(signer, audiences, tt.subject, tt.online, tt.nbf, tt.exp)
			if err != nil {
				t.Errorf("expected error to be nil, returned '%v'", err)
			}
			if len(token) == 0 {
				t.Error("expected token not to be empty")
			}

			result, err := verifier.Verify(token)
			if err != nil {
				t.Errorf("expected error to be nil, returned '%v'", err)
			}

			expectStringNotEmpty(t, tt.name+":result.ID", result.ID)
			expectStringEmpty(t, tt.name+":result.Fingerprint", result.Fingerprint)
			expectString(t, tt.name+":result.Subject", result.Subject, tt.subject)
			expectString(t, tt.name+":result.Audience", strings.Join(result.Audience, ":"), strings.Join(audiences, ":"))
			expectBool(t, tt.name+":result.IsOnline", result.IsOnline, tt.online)
			expectTimeVaguelyEqual(t, tt.name+":result.NotBefore", result.NotBefore, tt.nbf)
			expectTimeVaguelyEqual(t, tt.name+":result.Expires", result.Expires, tt.exp)

			expectClaim(t, tt.name+":result.Claims[sub]", result.Claims, jwt.String(jwt.Subject, tt.subject))
			expectClaim(t, tt.name+":result.Claims[onl]", result.Claims, jwt.Bool("onl", tt.online))
			expectClaim(t, tt.name+":result.Claims[aud]", result.Claims, jwt.Strings(jwt.Audience, audiences))
		})
	}
}

func TestJWTVerifier_ShouldSucceed_MultipleAud_OneValid(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)
	notBefore := time.Now().Add(-1 * time.Minute).UTC()
	expiry := time.Now().Add(time.Hour).UTC()

	token, err := jwt.Sign(
		signer,
		[]string{"test-audience", "another-audience", "some-other-test-audience"},
		"test-subject",
		false,
		notBefore, expiry,
	)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	expectBool(t, "result.IsOnline", result.IsOnline, false)
}

func TestJWTVerifier_ShouldSucceed_AlgorithmRS256(t *testing.T) {
	// signer := createSigner(t)
	verifier := createVerifier(t)

	privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	algSigner := &jwt.RSASigner{
		Algorithm:  jwt.RS256,
		PrivateKey: privateKey,
	}
	token, err := jwt.Sign(
		algSigner,
		[]string{"test-audience"},
		"test-subject",
		false,
		time.Now(), time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	expectString(t, "result.Subject", result.Subject, "test-subject")
}

func TestJWTVerifier_ShouldSucceed_AlgorithmRS384(t *testing.T) {
	// signer := createSigner(t)
	verifier := createVerifier(t)

	privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	algSigner := &jwt.RSASigner{
		Algorithm:  jwt.RS384,
		PrivateKey: privateKey,
	}
	token, err := jwt.Sign(
		algSigner,
		[]string{"test-audience"},
		"test-subject",
		false,
		time.Now(), time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	expectString(t, "result.Subject", result.Subject, "test-subject")
}

func TestJWTVerifier_ShouldSucceed_AlgorithmRS512(t *testing.T) {
	// signer := createSigner(t)
	verifier := createVerifier(t)

	privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	algSigner := &jwt.RSASigner{
		Algorithm:  jwt.RS512,
		PrivateKey: privateKey,
	}
	token, err := jwt.Sign(
		algSigner,
		[]string{"test-audience"},
		"test-subject",
		false,
		time.Now(), time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	expectString(t, "result.Subject", result.Subject, "test-subject")
}

func TestJWTVerifier_ShouldFail_AlgorithmHS256(t *testing.T) {
	// signer := createSigner(t)
	// verifier := createVerifier(t)

	privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	algSigner := &jwt.RSASigner{
		Algorithm:  "HS256",
		PrivateKey: privateKey,
	}
	token, err := jwt.Sign(
		algSigner,
		[]string{"test-audience"},
		"test-subject",
		false,
		time.Now(), time.Now().Add(time.Hour),
	)
	if !strings.Contains(err.Error(), "jwt: algorithm \"HS256\" not in use") {
		t.Errorf("expected error message '%v' to contain '%s'", err, "jwt: algorithm \"HS256\" not in use")
	}
	if len(token) != 0 {
		t.Error("expected token to be empty")
	}
}

func TestJWTVerifier_OnlineToken(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	token, err := jwt.Sign(
		signer,
		[]string{"test-audience"},
		"test-subject",
		true,
		time.Now(), time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	expectBool(t, "result.IsOnline", result.IsOnline, true)
	expectString(t, "result.Subject", result.Subject, "test-subject")
}

func TestJWTVerifier_AudienceShouldFail(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	token, err := jwt.Sign(
		signer,
		[]string{"not-audience"},
		"test-subject",
		false,
		time.Now(), time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	expectErrMatch(t, "jwt.ErrTokenInvalidAudience", err, jwt.ErrTokenInvalidAudience)
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	if strings.EqualFold(result.Subject, "test-subject") {
		t.Errorf("%s: expected not to equal '%s', returned '%s'", "result.Subject", "test-subject", result.Subject)
	}
}

func TestJWTVerifier_NotValidYet(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	token, err := jwt.Sign(
		signer,
		[]string{"test-audience"},
		"test-subject",
		false,
		time.Now().Add(time.Minute),
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	expectErrMatch(t, "jwt.ErrTokenTimeNotValid", err, jwt.ErrTokenTimeNotValid)
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	if strings.EqualFold(result.Subject, "test-subject") {
		t.Errorf("%s: expected not to equal '%s', returned '%s'", "result.Subject", "test-subject", result.Subject)
	}
}

func TestJWTVerifier_Expired(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	token, err := jwt.Sign(
		signer,
		[]string{"test-audience"},
		"test-subject",
		false,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(-1*time.Minute),
	)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	expectErrMatch(t, "jwt.ErrTokenTimeNotValid", err, jwt.ErrTokenTimeNotValid)
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	if strings.EqualFold(result.Subject, "test-subject") {
		t.Errorf("%s: expected not to equal '%s', returned '%s'", "result.Subject", "test-subject", result.Subject)
	}
}

func TestJWTVerifier_GarbageToken(t *testing.T) {
	verifier := createVerifier(t)

	result, err := verifier.Verify([]byte("garbage"))
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	if strings.EqualFold(result.Subject, "test-subject") {
		t.Errorf("%s: expected not to equal '%s', returned '%s'", "result.Subject", "test-subject", result.Subject)
	}
}

func TestJWTVerifier_ValidStructureGarbageToken(t *testing.T) {
	verifier := createVerifier(t)

	result, err := verifier.Verify([]byte("Z2FyYmFnZQ==.Z2FyYmFnZQ==.Z2FyYmFnZQ=="))
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	if strings.EqualFold(result.Subject, "test-subject") {
		t.Errorf("%s: expected not to equal '%s', returned '%s'", "result.Subject", "test-subject", result.Subject)
	}
}

func TestJWTVerifier_ValidStructureValidJSONGarbageToken(t *testing.T) {
	verifier := createVerifier(t)

	result, err := verifier.Verify([]byte("e30=.e30=.e30="))
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	if strings.EqualFold(result.Subject, "test-subject") {
		t.Errorf("%s: expected not to equal '%s', returned '%s'", "result.Subject", "test-subject", result.Subject)
	}
}

func TestJWTVerifier_ValidJWTInvalidSigning(t *testing.T) {
	verifier := createVerifier(t)

	result, err := verifier.Verify([]byte(
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I" +
			"kpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
			"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"))
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	if strings.EqualFold(result.Subject, "test-subject") {
		t.Errorf("%s: expected not to equal '%s', returned '%s'", "result.Subject", "test-subject", result.Subject)
	}
}
