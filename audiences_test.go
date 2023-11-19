package jwt_test

import (
	"testing"

	"github.com/na4ma4/jwt/v2"
)

func ExpectBool(t *testing.T, name string, expect, input bool) {
	t.Helper()
	if expect != input {
		t.Errorf("%s expected '%t', received '%t'", name, expect, input)
	}
}

func TestAudienceSliceEmptyClaimAudience(t *testing.T) {
	asNone := jwt.AudienceSlice{}
	emptyList := []string{}

	ExpectBool(t, "should not match single audience", asNone.Has("test-audience"), false)
	ExpectBool(t, "should not match empty list of audiences (one-of)", asNone.HasAny(emptyList), false)
	ExpectBool(t, "should not match empty list of audiences (all)", asNone.HasAll(emptyList), false)
	ExpectBool(t, "should not match empty list of audiences (only)", asNone.HasOnly(emptyList), false)
}

func TestAudienceSliceSingleClaimAudience(t *testing.T) {
	asOne := jwt.AudienceSlice{"test-audience"}

	ExpectBool(t, "should match single valid audience", asOne.Has("test-audience"), true)
	ExpectBool(t, "should not match single invalid audience", asOne.Has("test-audience2"), false)
	ExpectBool(t, "should ignore case when matching", asOne.Has("TEST-AUDIENCE"), true)
	ExpectBool(t, "should ignore case when matching", asOne.Has("TEST-AUDIENCE"), true)
}

func TestAudienceSliceSingleClaimAudience_HasAny(t *testing.T) {
	asOne := jwt.AudienceSlice{"test-audience"}

	ExpectBool(t, "should match list of audiences (one-of)", asOne.HasAny([]string{"test-audience"}), true)

	ExpectBool(
		t,
		"should match list of audiences (valid,invalid) (one-of)",
		asOne.HasAny([]string{"test-audience2",
			"test-audience"}),
		true,
	)
	ExpectBool(
		t,
		"should match list of audiences (valid,invalid) (one-of)",
		asOne.HasAny([]string{"test-audience", "test-audience2"}),
		true,
	)

	ExpectBool(
		t,
		"should not match list of invalid audiences (one-of)",
		asOne.HasAny([]string{"test-audience2"}),
		false,
	)
	ExpectBool(
		t,
		"should not match list of invalid audiences (one-of)",
		asOne.HasAny([]string{"test-audience2",
			"TEST-AUDIENCE2"}),
		false,
	)

	ExpectBool(
		t,
		"should ignore case when matching list of audiences (one-of)",
		asOne.HasAny([]string{"TEST-AUDIENCE"}),
		true,
	)
}

func TestAudienceSliceSingleClaimAudience_HasAll(t *testing.T) {
	asOne := jwt.AudienceSlice{"test-audience"}

	ExpectBool(t, "should match list of audiences (all-of)", asOne.HasAll([]string{"test-audience"}), true)

	ExpectBool(t, "should not match list of partially valid audiences (all-of)", asOne.HasAll([]string{"test-audience2", "test-audience"}), false)
	ExpectBool(t, "should not match list of partially valid audiences (all-of)", asOne.HasAll([]string{"test-audience", "test-audience2"}), false)

	ExpectBool(t, "should not match list of invalid audiences (all-of)", asOne.HasAll([]string{"test-audience2"}), false)

	ExpectBool(t, "should not match list of invalid audiences (all-of)", asOne.HasAll([]string{"test-audience2", "TEST-AUDIENCE2"}), false)

	ExpectBool(t, "should ignore case when matching list of audiences (all-of)", asOne.HasAll([]string{"TEST-AUDIENCE"}), true)
}

func TestAudienceSliceSingleClaimAudience_HasOnly(t *testing.T) {
	asOne := jwt.AudienceSlice{"test-audience"}

	ExpectBool(t, "should match list of matching audiences (only)", asOne.HasOnly([]string{"test-audience"}), true)
	ExpectBool(t, "should not match list of audiences containing one valid (invalid,valid) (only)", asOne.HasOnly([]string{"test-audience2", "test-audience"}), false)
	ExpectBool(t, "should not match list of audiences containing one valid (valid,invalid) (only)", asOne.HasOnly([]string{"test-audience", "test-audience2"}), false)
	ExpectBool(t, "should not match list of invalid audiences (only)", asOne.HasOnly([]string{"test-audience2"}), false)
	ExpectBool(t, "should not match list of invalid audiences (only)", asOne.HasOnly([]string{"test-audience2", "TEST-AUDIENCE2"}), false)
	ExpectBool(t, "should ignore case when matching list of audiences (only)", asOne.HasOnly([]string{"TEST-AUDIENCE"}), true)
}

func TestAudienceSliceMultipleClaimAudience(t *testing.T) {
	asMany := jwt.AudienceSlice{"test-audience", "2nd-test-audience", "3rd-test-audience"}

	ExpectBool(t, "should match single valid audience", asMany.Has("test-audience"), true)
	ExpectBool(t, "should not match single invalid audience", asMany.Has("test-audience2"), false)
	ExpectBool(t, "should ignore case when matching", asMany.Has("TEST-AUDIENCE"), true)
	ExpectBool(t, "should ignore case when matching", asMany.Has("TEST-AUDIENCE"), true)
}

func TestAudienceSliceMultipleClaimAudience_HasAny(t *testing.T) {
	asMany := jwt.AudienceSlice{"test-audience", "2nd-test-audience", "3rd-test-audience"}

	ExpectBool(t, "should match list of audiences (one-of)", asMany.HasAny([]string{"test-audience"}), true)
	ExpectBool(t, "should match list of audiences (invalid,valid) (one-of)", asMany.HasAny([]string{"test-audience2", "test-audience"}), true)
	ExpectBool(t, "should match list of audiences (valid,invalid) (one-of)", asMany.HasAny([]string{"test-audience", "test-audience2"}), true)
	ExpectBool(t, "should not match list of invalid audiences (one-of)", asMany.HasAny([]string{"test-audience2"}), false)
	ExpectBool(t, "should not match list of invalid audiences (one-of)", asMany.HasAny([]string{"test-audience2", "TEST-AUDIENCE2"}), false)
	ExpectBool(t, "should ignore case when matching list of audiences (one-of)", asMany.HasAny([]string{"TEST-AUDIENCE"}), true)
}

func TestAudienceSliceMultipleClaimAudience_HasAll(t *testing.T) {
	asMany := jwt.AudienceSlice{"test-audience", "2nd-test-audience", "3rd-test-audience"}

	ExpectBool(t, "should match list of matching audiences (all-of)", asMany.HasAll([]string{"test-audience"}), true)
	ExpectBool(t, "should match list of matching audiences (all-of)", asMany.HasAll([]string{"test-audience", "2nd-test-audience"}), true)
	ExpectBool(t, "should match list of matching audiences (all-of)", asMany.HasAll([]string{"test-audience", "3rd-test-audience"}), true)
	ExpectBool(t, "should match list of matching audiences (all-of)", asMany.HasAll([]string{"test-audience", "2nd-test-audience", "3rd-test-audience"}), true)

	ExpectBool(t, "should not match list of audiences combining valid and invalid (all-of)", asMany.HasAll([]string{"test-audience2", "test-audience"}), false)
	ExpectBool(t, "should not match list of audiences combining valid and invalid (all-of)", asMany.HasAll([]string{"test-audience", "test-audience2"}), false)

	ExpectBool(t, "should not match list of invalid audiences (all-of)", asMany.HasAll([]string{"test-audience2"}), false)
	ExpectBool(t, "should not match list of invalid audiences (all-of)", asMany.HasAll([]string{"test-audience2", "TEST-AUDIENCE2"}), false)

	ExpectBool(t, "should ignore case when matching list of audiences (all-of)", asMany.HasAll([]string{"TEST-AUDIENCE"}), true)
}

func TestAudienceSliceMultipleClaimAudience_HasOnly(t *testing.T) {
	asMany := jwt.AudienceSlice{"test-audience", "2nd-test-audience", "3rd-test-audience"}

	ExpectBool(t, "should match list of matching audiences (only)", asMany.HasOnly([]string{"test-audience", "2nd-test-audience", "3rd-test-audience"}), true)

	ExpectBool(t, "should not match incomplete list of matching audiences (only)", asMany.Has("test-audience"), true)
	ExpectBool(t, "should not match incomplete list of matching audiences (only)", asMany.HasOnly([]string{"test-audience"}), false)
	ExpectBool(t, "should not match incomplete list of matching audiences (only)", asMany.HasOnly([]string{"test-audience", "2nd-test-audience"}), false)
	ExpectBool(t, "should not match incomplete list of matching audiences (only)", asMany.HasOnly([]string{"test-audience", "3rd-test-audience"}), false)

	ExpectBool(t, "should not match list of audiences containing one valid (only)", asMany.HasOnly([]string{"test-audience2", "test-audience"}), false)
	ExpectBool(t, "should not match list of audiences containing one valid (only)", asMany.HasOnly([]string{"test-audience", "test-audience2"}), false)

	ExpectBool(t, "should not match list of invalid audiences (only)", asMany.HasOnly([]string{"test-audience2"}), false)
	ExpectBool(t, "should not match list of invalid audiences (only)", asMany.HasOnly([]string{"test-audience2", "TEST-AUDIENCE2"}), false)

	ExpectBool(t, "should ignore case when matching list of audiences (only)", asMany.HasOnly([]string{"TEST-AUDIENCE", "2ND-TEST-AUDIENCE", "3rd-test-audience"}), true)
	ExpectBool(t, "should ignore case when matching list of audiences (only)", asMany.HasOnly([]string{"TEST-AUDIENCE", "2ND-TEST-AUDIENCE", "3rd-test-audience"}), true)
	ExpectBool(t, "should ignore case when matching list of audiences (only)", asMany.HasOnly([]string{"test-audience", "2ND-TEST-AUDIENCE", "3rd-test-audience"}), true)
	ExpectBool(t, "should ignore case when matching list of audiences (only)", asMany.HasOnly([]string{"TEST-AUDIENCE", "2nd-test-audience", "3rd-test-audience"}), true)
}
