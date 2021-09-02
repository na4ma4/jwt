package jwt_test

import (
	"github.com/na4ma4/jwt/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//nolint:dupl // plenty of duplication here.
var _ = Describe("Audience Slice", func() {
	Context("Empty Claim Audience", func() {
		asNone := jwt.AudienceSlice{}
		emptyList := []string{}

		It("should not match single audience", func() {
			Expect(asNone.Has("test-audience")).To(BeFalse())
		})

		It("should not match empty list of audiences (one-of)", func() {
			Expect(asNone.HasAny(emptyList)).To(BeFalse())
		})

		It("should not match empty list of audiences (all)", func() {
			Expect(asNone.HasAll(emptyList)).To(BeFalse())
		})

		It("should not match empty list of audiences (only)", func() {
			Expect(asNone.HasOnly(emptyList)).To(BeFalse())
		})
	})

	Context("Single Claim Audience", func() {
		asOne := jwt.AudienceSlice{"test-audience"}

		It("should match single valid audience", func() {
			Expect(asOne.Has("test-audience")).To(BeTrue())
		})

		It("should not match single invalid audience", func() {
			Expect(asOne.Has("test-audience2")).To(BeFalse())
		})

		It("should ignore case when matching", func() {
			Expect(asOne.Has("TEST-AUDIENCE")).To(BeTrue())
		})

		It("should ignore case when matching", func() {
			Expect(asOne.Has("TEST-AUDIENCE")).To(BeTrue())
		})

		Context("HasAny", func() {
			It("should match list of audiences (one-of)", func() {
				Expect(asOne.HasAny([]string{"test-audience"})).To(BeTrue())
			})

			It("should match list of audiences (valid,invalid) (one-of)", func() {
				Expect(asOne.HasAny([]string{"test-audience2", "test-audience"})).To(BeTrue())
				Expect(asOne.HasAny([]string{"test-audience", "test-audience2"})).To(BeTrue())
			})

			It("should not match list of invalid audiences (one-of)", func() {
				Expect(asOne.HasAny([]string{"test-audience2"})).To(BeFalse())
				Expect(asOne.HasAny([]string{"test-audience2", "TEST-AUDIENCE2"})).To(BeFalse())
			})

			It("should ignore case when matching list of audiences (one-of)", func() {
				Expect(asOne.HasAny([]string{"TEST-AUDIENCE"})).To(BeTrue())
			})
		})

		Context("HasAll", func() {
			It("should match list of audiences (all-of)", func() {
				Expect(asOne.HasAll([]string{"test-audience"})).To(BeTrue())
			})

			It("should not match list of partially valid audiences (all-of)", func() {
				Expect(asOne.HasAll([]string{"test-audience2", "test-audience"})).To(BeFalse())
				Expect(asOne.HasAll([]string{"test-audience", "test-audience2"})).To(BeFalse())
			})

			It("should not match list of invalid audiences (all-of)", func() {
				Expect(asOne.HasAll([]string{"test-audience2"})).To(BeFalse())
			})

			It("should not match list of invalid audiences (all-of)", func() {
				Expect(asOne.HasAll([]string{"test-audience2", "TEST-AUDIENCE2"})).To(BeFalse())
			})

			It("should ignore case when matching list of audiences (all-of)", func() {
				Expect(asOne.HasAll([]string{"TEST-AUDIENCE"})).To(BeTrue())
			})
		})

		Context("HasOnly", func() {
			It("should match list of matching audiences (only)", func() {
				Expect(asOne.HasOnly([]string{"test-audience"})).To(BeTrue())
			})

			It("should not match list of audiences containing one valid (invalid,valid) (only)", func() {
				Expect(asOne.HasOnly([]string{"test-audience2", "test-audience"})).To(BeFalse())
			})

			It("should not match list of audiences containing one valid (valid,invalid) (only)", func() {
				Expect(asOne.HasOnly([]string{"test-audience", "test-audience2"})).To(BeFalse())
			})

			It("should not match list of invalid audiences (only)", func() {
				Expect(asOne.HasOnly([]string{"test-audience2"})).To(BeFalse())
			})

			It("should not match list of invalid audiences (only)", func() {
				Expect(asOne.HasOnly([]string{"test-audience2", "TEST-AUDIENCE2"})).To(BeFalse())
			})

			It("should ignore case when matching list of audiences (only)", func() {
				Expect(asOne.HasOnly([]string{"TEST-AUDIENCE"})).To(BeTrue())
			})
		})
	})

	Context("Multi Claim Audience", func() {
		asMany := jwt.AudienceSlice{"test-audience", "2nd-test-audience", "3rd-test-audience"}

		It("should match single valid audience", func() {
			Expect(asMany.Has("test-audience")).To(BeTrue())
		})

		It("should not match single invalid audience", func() {
			Expect(asMany.Has("test-audience2")).To(BeFalse())
		})

		It("should ignore case when matching", func() {
			Expect(asMany.Has("TEST-AUDIENCE")).To(BeTrue())
		})

		It("should ignore case when matching", func() {
			Expect(asMany.Has("TEST-AUDIENCE")).To(BeTrue())
		})

		Context("HasAny", func() {
			It("should match list of audiences (one-of)", func() {
				Expect(asMany.HasAny([]string{"test-audience"})).To(BeTrue())
			})

			It("should match list of audiences (invalid,valid) (one-of)", func() {
				Expect(asMany.HasAny([]string{"test-audience2", "test-audience"})).To(BeTrue())
			})

			It("should match list of audiences (valid,invalid) (one-of)", func() {
				Expect(asMany.HasAny([]string{"test-audience", "test-audience2"})).To(BeTrue())
			})

			It("should not match list of invalid audiences (one-of)", func() {
				Expect(asMany.HasAny([]string{"test-audience2"})).To(BeFalse())
			})

			It("should not match list of invalid audiences (one-of)", func() {
				Expect(asMany.HasAny([]string{"test-audience2", "TEST-AUDIENCE2"})).To(BeFalse())
			})

			It("should ignore case when matching list of audiences (one-of)", func() {
				Expect(asMany.HasAny([]string{"TEST-AUDIENCE"})).To(BeTrue())
			})
		})

		Context("HasAll", func() {
			It("should match list of matching audiences (all-of)", func() {
				Expect(asMany.HasAll([]string{"test-audience"})).To(BeTrue())
				Expect(asMany.HasAll([]string{"test-audience", "2nd-test-audience"})).To(BeTrue())
				Expect(asMany.HasAll([]string{"test-audience", "3rd-test-audience"})).To(BeTrue())
				Expect(asMany.HasAll([]string{"test-audience", "2nd-test-audience", "3rd-test-audience"})).To(BeTrue())
			})

			It("should not match list of audiences combining valid and invalid (all-of)", func() {
				Expect(asMany.HasAll([]string{"test-audience2", "test-audience"})).To(BeFalse())
				Expect(asMany.HasAll([]string{"test-audience", "test-audience2"})).To(BeFalse())
			})

			It("should not match list of invalid audiences (all-of)", func() {
				Expect(asMany.HasAll([]string{"test-audience2"})).To(BeFalse())
				Expect(asMany.HasAll([]string{"test-audience2", "TEST-AUDIENCE2"})).To(BeFalse())
			})

			It("should ignore case when matching list of audiences (all-of)", func() {
				Expect(asMany.HasAll([]string{"TEST-AUDIENCE"})).To(BeTrue())
			})
		})

		Context("HasOnly", func() {
			It("should match list of matching audiences (only)", func() {
				Expect(asMany.HasOnly([]string{"test-audience", "2nd-test-audience", "3rd-test-audience"})).To(BeTrue())
			})

			It("should not match incomplete list of matching audiences (only)", func() {
				Expect(asMany.Has("test-audience")).To(BeTrue())
				Expect(asMany.HasOnly([]string{"test-audience"})).To(BeFalse())
				Expect(asMany.HasOnly([]string{"test-audience", "2nd-test-audience"})).To(BeFalse())
				Expect(asMany.HasOnly([]string{"test-audience", "3rd-test-audience"})).To(BeFalse())
			})

			It("should not match list of audiences containing one valid (only)", func() {
				Expect(asMany.HasOnly([]string{"test-audience2", "test-audience"})).To(BeFalse())
				Expect(asMany.HasOnly([]string{"test-audience", "test-audience2"})).To(BeFalse())
			})

			It("should not match list of invalid audiences (only)", func() {
				Expect(asMany.HasOnly([]string{"test-audience2"})).To(BeFalse())
				Expect(asMany.HasOnly([]string{"test-audience2", "TEST-AUDIENCE2"})).To(BeFalse())
			})

			It("should ignore case when matching list of audiences (only)", func() {
				Expect(asMany.HasOnly([]string{"TEST-AUDIENCE", "2ND-TEST-AUDIENCE", "3rd-test-audience"})).To(BeTrue())
				Expect(asMany.HasOnly([]string{"TEST-AUDIENCE", "2ND-TEST-AUDIENCE", "3rd-test-audience"})).To(BeTrue())
				Expect(asMany.HasOnly([]string{"test-audience", "2ND-TEST-AUDIENCE", "3rd-test-audience"})).To(BeTrue())
				Expect(asMany.HasOnly([]string{"TEST-AUDIENCE", "2nd-test-audience", "3rd-test-audience"})).To(BeTrue())
			})
		})
	})
})
