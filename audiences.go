package jwt

import "strings"

// AudienceSlice is a helper type for taking a slice of strings and allowing
// it to be checked for valid audiences.
type AudienceSlice []string

// Has checks to see if an AudienceSlice contains a specific audience.
func (a AudienceSlice) Has(audience string) bool {
	for _, aud := range a {
		if strings.EqualFold(aud, audience) {
			return true
		}
	}

	return false
}

// HasAny checks to see if any audience supplied is matched by any audience in the slice.
func (a AudienceSlice) HasAny(audiences []string) bool {
	for _, aud := range a {
		for _, checkaud := range audiences {
			if strings.EqualFold(aud, checkaud) {
				return true
			}
		}
	}

	return false
}

// HasAll checks to see if all audiences supplied is matched by any audience in the slice.
// if supplied audience list is empty, returns false.
func (a AudienceSlice) HasAll(audiences []string) bool {
	if len(audiences) == 0 {
		return false
	}

	for _, checkaud := range audiences {
		found := false

		for _, aud := range a {
			if strings.EqualFold(aud, checkaud) {
				found = true
			}
		}

		if !found {
			return false
		}
	}

	return true
}

// HasOnly checks to see if all audiences supplied is matched by all audience in the slice.
// if supplied audience list is empty, returns false.
func (a AudienceSlice) HasOnly(audiences []string) bool {
	if len(audiences) == 0 {
		return false
	}

	if len(audiences) != len(a) {
		return false
	}

	return a.HasAll(audiences)
}

// Slice returns the AudienceSlice as the underlying string slice.
func (a AudienceSlice) Slice() []string {
	return a
}
