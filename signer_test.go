package jwt_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/na4ma4/jwt/v2"
)

func expectBool(t *testing.T, name string, value, expect bool) {
	t.Helper()

	if value != expect {
		t.Errorf("%s: expected '%t', received '%t'", name, expect, value)
	}
}

func expectString(t *testing.T, name string, value, expect string) {
	t.Helper()

	if value != expect {
		t.Errorf("%s: expected '%s', received '%s'", name, expect, value)
	}
}

func expectStringNotEmpty(t *testing.T, name string, value string) {
	t.Helper()

	if len(value) == 0 {
		t.Errorf("%s: expected not empty, received '%s'", name, value)
	}
}

func expectStringEmpty(t *testing.T, name string, value string) {
	t.Helper()

	if len(value) > 0 {
		t.Errorf("%s: expected empty, received '%s'(%d)", name, value, len(value))
	}
}

func expectByteStringEmpty(t *testing.T, name string, value []byte) {
	t.Helper()

	if len(value) > 0 {
		t.Errorf("%s: expected empty, received '%s'", name, value)
	}
}

func expectSliceEmpty(t *testing.T, name string, value []string) {
	t.Helper()

	if len(value) > 0 {
		t.Errorf("%s: expected empty, received '%s'", name, value)
	}
}

func expectTimeVaguelyEqual(t *testing.T, name string, value, expect time.Time) {
	t.Helper()

	if expect.Unix() != value.Unix() {
		t.Errorf("%s: expected vaguely '%s', received '%s'", name, expect.String(), value.String())
	}
}

func expectTimeZero(t *testing.T, name string, value time.Time) {
	t.Helper()

	if !value.IsZero() {
		t.Errorf("%s: expected time to be zero, but received '%s'", name, value.String())
	}
}

//nolint:unparam // might reuse this code or combine into something more generic.
func expectStringElement(t *testing.T, name string, value []string, expect string) {
	t.Helper()

	for _, v := range value {
		if v == expect {
			return
		}
	}

	t.Errorf("%s: element '%s' not found in slice", name, expect)
}

func expectClaim(t *testing.T, name string, value map[string]jwt.Claim, expect jwt.Claim) {
	t.Helper()

	for _, v := range value {
		if v.Key == expect.Key {
			switch v.Type { //nolint:exhaustive // unit tests
			case jwt.StringType:
				if v.String == expect.String {
					return
				}
			case jwt.StringsType:
				bv, bok := v.Interface.([]string)
				ev, eok := expect.Interface.([]string)
				if bok && eok && strings.Join(bv, ":") == strings.Join(ev, ":") {
					return
				}
			case jwt.BoolType:
				bv, bok := v.Interface.(bool)
				ev, eok := expect.Interface.(bool)
				if bok && eok && bv == ev {
					return
				}
			default:
				t.Errorf("unexpected claim type: %d", v.Type)
			}
		}
	}

	t.Errorf("%s: claim '%s' not found in slice", name, expect.Key)
}

func expectErrMatch(t *testing.T, name string, err, expect error) {
	t.Helper()

	if !errors.Is(err, expect) {
		t.Errorf("%s: expected err '%v' to match type '%v'", name, err, expect)
	}
}

func TestJWTSigner_ShouldSucceed(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	nbfTime := time.Now().UTC()
	expTime := time.Now().Add(time.Hour).UTC()

	subject := jwt.String(jwt.Subject, "subject")
	audience := jwt.Strings(jwt.Audience, []string{"test-audience"})
	notBefore := jwt.Time(jwt.NotBefore, nbfTime)
	expiry := jwt.Time(jwt.Expires, expTime)

	token, err := signer.SignClaims(subject, audience, expiry, notBefore)
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
	expectString(t, "result.Subject", result.Subject, "subject")
	expectStringNotEmpty(t, "result.ID", result.ID)
	expectStringElement(t, "result.Audience[test-audience]", result.Audience, "test-audience")
	if len(result.Audience) != 1 {
		t.Errorf("result.Audience: expected length '1', returned '%d'", len(result.Audience))
	}
	expectStringEmpty(t, "result.Fingerprint", result.Fingerprint)
	expectTimeVaguelyEqual(t, "result.NotBefore", result.NotBefore, nbfTime)
	expectTimeVaguelyEqual(t, "result.Expires", result.Expires, expTime)
}

func TestJWTSigner_ShouldSucceedEvenWithNoClaims(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	token, err := signer.SignClaims()
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	expectErrMatch(t, "jwt.ErrTokenInvalidAudience", err, jwt.ErrTokenInvalidAudience)
	expectStringEmpty(t, "result.Subject", result.Subject)
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	expectStringEmpty(t, "result.ID", result.ID)
	expectSliceEmpty(t, "result.Audience", result.Audience)
	expectStringEmpty(t, "result.Fingerprint", result.Fingerprint)
	expectTimeZero(t, "result.NotBefore", result.NotBefore)
	expectTimeZero(t, "result.Expires", result.Expires)
}

func TestJWTSigner_ShouldFailWithInvalidTypeForRegisteredClaim_NBT(t *testing.T) {
	signer := createSigner(t)
	notBefore := jwt.String(jwt.NotBefore, "not a time")

	token, err := signer.SignClaims(notBefore)
	expectErrMatch(t, "jwt.ErrInvalidTypeForClaim", err, jwt.ErrInvalidTypeForClaim)
	expectByteStringEmpty(t, "token", token)
}

func TestJWTSigner_ShouldFailWithInvalidTypeForRegisteredClaim_EXP(t *testing.T) {
	signer := createSigner(t)
	expires := jwt.String(jwt.Expires, "not a time")

	token, err := signer.SignClaims(expires)
	expectErrMatch(t, "jwt.ErrInvalidTypeForClaim", err, jwt.ErrInvalidTypeForClaim)
	expectByteStringEmpty(t, "token", token)
}

func TestJWTSigner_ShouldFailWithInvalidTypeForRegisteredClaim_IAT(t *testing.T) {
	signer := createSigner(t)
	issued := jwt.String(jwt.Issued, "not a time")

	token, err := signer.SignClaims(issued)
	expectErrMatch(t, "jwt.ErrInvalidTypeForClaim", err, jwt.ErrInvalidTypeForClaim)
	expectByteStringEmpty(t, "token", token)
}

func TestJWTSigner_ShouldFailWithInvalidAudience(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	token, err := signer.SignClaims()
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if len(token) == 0 {
		t.Error("expected token not to be empty")
	}

	result, err := verifier.Verify(token)
	expectErrMatch(t, "jwt.ErrTokenInvalidAudience", err, jwt.ErrTokenInvalidAudience)
	expectSliceEmpty(t, "result.Audience", result.Audience)
}

func TestJWTSigner_ShouldSucceed_TokenWithNoExpiry(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	token, err := signer.SignClaims(
		jwt.String(jwt.Subject, "user"),
		jwt.Strings(jwt.Audience, []string{"test-audience"}),
		jwt.Bool("onl", true),
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
	expectStringElement(t, "result.Audience[test-audience]", result.Audience, "test-audience")
	if len(result.Audience) != 1 {
		t.Errorf("result.Audience: expected length '1', returned '%d'", len(result.Audience))
	}
}

func TestJWTSigner_ShouldSucceed_CustomField(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	nbfTime := time.Now().UTC()
	expTime := time.Now().Add(time.Hour).UTC()

	subject := jwt.String(jwt.Subject, "subject")
	audience := jwt.Strings(jwt.Audience, []string{"test-audience"})
	notBefore := jwt.Time(jwt.NotBefore, nbfTime)
	expiry := jwt.Time(jwt.Expires, expTime)
	custom := jwt.String("foo", "bar")

	token, err := signer.SignClaims(subject, audience, expiry, notBefore, custom)
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
	expectString(t, "result.Subject", result.Subject, "subject")
	expectStringNotEmpty(t, "result.ID", result.ID)
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	expectStringElement(t, "result.Audience[test-audience]", result.Audience, "test-audience")
	if len(result.Audience) != 1 {
		t.Errorf("result.Audience: expected length '1', returned '%d'", len(result.Audience))
	}
	expectStringEmpty(t, "result.Fingerprint", result.Fingerprint)
	expectTimeVaguelyEqual(t, "result.NotBefore", result.NotBefore, nbfTime)
	expectTimeVaguelyEqual(t, "result.Expires", result.Expires, expTime)

	expectClaim(t, "result.Claims[custom]", result.Claims, custom)
}

func TestJWTSigner_ShouldSucceed_OnlineField(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	nbfTime := time.Now().UTC()
	expTime := time.Now().Add(time.Hour).UTC()

	subject := jwt.String(jwt.Subject, "subject")
	audience := jwt.Strings(jwt.Audience, []string{"test-audience"})
	notBefore := jwt.Time(jwt.NotBefore, nbfTime)
	expiry := jwt.Time(jwt.Expires, expTime)
	online := jwt.Bool("onl", true)

	token, err := signer.SignClaims(subject, audience, expiry, notBefore, online)
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
	expectString(t, "result.Subject", result.Subject, "subject")
	expectBool(t, "result.IsOnline", result.IsOnline, true)
	expectStringNotEmpty(t, "result.ID", result.ID)
	expectStringElement(t, "result.Audience[test-audience]", result.Audience, "test-audience")
	if len(result.Audience) != 1 {
		t.Errorf("result.Audience: expected length '1', returned '%d'", len(result.Audience))
	}
	expectStringEmpty(t, "result.Fingerprint", result.Fingerprint)
	expectTimeVaguelyEqual(t, "result.NotBefore", result.NotBefore, nbfTime)
	expectTimeVaguelyEqual(t, "result.Expires", result.Expires, expTime)

	expectClaim(t, "result.Claims[onl]", result.Claims, online)
}

func TestJWTSigner_ShouldSucceed_OnlineAndFingerprint(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	nbfTime := time.Now().UTC()
	expTime := time.Now().Add(time.Hour).UTC()

	subject := jwt.String(jwt.Subject, "subject")
	audience := jwt.Strings(jwt.Audience, []string{"test-audience"})
	notBefore := jwt.Time(jwt.NotBefore, nbfTime)
	expiry := jwt.Time(jwt.Expires, expTime)
	online := jwt.Bool("onl", true)
	fprint := jwt.String("fpt", "fingerpainting-is-fun")

	token, err := signer.SignClaims(subject, audience, expiry, notBefore, online, fprint)
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
	expectString(t, "result.Subject", result.Subject, "subject")
	expectBool(t, "result.IsOnline", result.IsOnline, true)
	expectStringNotEmpty(t, "result.ID", result.ID)
	expectStringElement(t, "result.Audience", result.Audience, "test-audience")
	if len(result.Audience) != 1 {
		t.Errorf("result.Audience: expected length '1', returned '%d'", len(result.Audience))
	}
	expectString(t, "result.Fingerprint", result.Fingerprint, "fingerpainting-is-fun")
	expectTimeVaguelyEqual(t, "result.NotBefore", result.NotBefore, nbfTime)
	expectTimeVaguelyEqual(t, "result.Expires", result.Expires, expTime)
}

func TestJWTSigner_ShouldSucceed_CarryCustomID(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	id := jwt.String("jti", "ponies")
	audience := jwt.Strings(jwt.Audience, []string{"test-audience"})

	token, err := signer.SignClaims(id, audience)
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
	expectStringEmpty(t, "result.Subject", result.Subject)
	expectBool(t, "result.IsOnline", result.IsOnline, false)
	expectString(t, "result.ID", result.ID, "ponies")
	expectStringElement(t, "result.Audience", result.Audience, "test-audience")
	if len(result.Audience) != 1 {
		t.Errorf("result.Audience: expected length '1', returned '%d'", len(result.Audience))
	}
	expectStringEmpty(t, "result.Fingerprint", result.Fingerprint)
	expectTimeZero(t, "result.NotBefore", result.NotBefore)
	expectTimeZero(t, "result.Expires", result.Expires)
}

func TestJWTSigner_ShouldSucceed_OnlyLastKeyUsed(t *testing.T) {
	signer := createSigner(t)
	verifier := createVerifier(t)

	token, err := signer.SignClaims(
		jwt.String(jwt.Subject, "subject"),
		jwt.Strings(jwt.Audience, []string{"test-audience"}),
		jwt.String(jwt.Subject, "new-subject"),
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
	expectString(t, "result.Subject", result.Subject, "new-subject")
	expectStringNotEmpty(t, "result.ID", result.ID)
	expectStringElement(t, "result.Audience", result.Audience, "test-audience")
	if len(result.Audience) != 1 {
		t.Errorf("result.Audience: expected length '1', returned '%d'", len(result.Audience))
	}
	expectStringEmpty(t, "result.Fingerprint", result.Fingerprint)
	expectTimeZero(t, "result.NotBefore", result.NotBefore)
	expectTimeZero(t, "result.Expires", result.Expires)
}
