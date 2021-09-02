package jwt_test

import (
	"time"

	"github.com/na4ma4/jwt/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("JWT Verifier and Signer", func() {
	var signer jwt.Signer
	var verifier jwt.Verifier
	var notBefore time.Time
	var expiry time.Time

	BeforeEach(func() {
		signer = createSigner()
		verifier = createVerifier()
		notBefore = time.Now().Add(-1 * time.Minute).UTC()
		expiry = time.Now().Add(time.Hour).UTC()
	})

	DescribeTable("should succeed",
		func(audience string, subject string, online bool, nbf, exp time.Time) {
			audiences := jwt.AudienceSlice{audience}
			token, err := jwt.Sign(signer, audiences, subject, online, nbf, exp)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			result, err := verifier.Verify(token)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.ID).NotTo(BeEmpty())
			Expect(result.Fingerprint).To(BeEmpty())
			Expect(result.Subject).To(Equal(subject))
			Expect(result.Audience).To(Equal(audiences))
			Expect(result.IsOnline).To(Equal(online))
			Expect(result.NotBefore).To(BeTemporally("~", nbf, time.Microsecond))
			Expect(result.Expires).To(BeTemporally("~", exp, time.Microsecond))

			Expect(result.Claims).To(ContainElement(jwt.String(jwt.Subject, subject)))
			Expect(result.Claims).To(ContainElement(jwt.Bool("onl", online)))
			Expect(result.Claims).To(ContainElement(jwt.Strings(jwt.Audience, audiences)))
		},
		Entry(
			"primary audience token",
			"test-audience", "test-subject", false, time.Now().Add(-1*time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		),
		Entry(
			"secondary audience token",
			"second-test-audience", "test-subject", false, time.Now().Add(-1*time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		),
		Entry(
			"standard token",
			"test-audience", "test-subject", false, time.Now().Add(-1*time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		),
		Entry(
			"offline with array of claims",
			"test-audience", "test-subject", false, time.Now().Add(-1*time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		),
		Entry(
			"online with array of claims",
			"test-audience", "test-subject", true, time.Now().Add(-1*time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		),
	)

	It("should succeed, multiple audiences, one valid", func() {
		token, err := jwt.Sign(
			signer,
			[]string{"test-audience", "another-audience", "some-other-test-audience"},
			"test-subject",
			false,
			notBefore, expiry,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
	})

	It("should succeed, Algorithm RS256", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
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
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("test-subject"))
	})

	It("should succeed, Algorithm RS384", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
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
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("test-subject"))
	})

	It("should succeed, Algorithm RS512", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
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
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("test-subject"))
	})

	It("should fail, invalid algorithm HS256", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
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
		Expect(err.Error()).To(ContainSubstring("jwt: algorithm \"HS256\" not in use"))
		Expect(token).To(BeEmpty())
	})

	It("online token", func() {
		token, err := jwt.Sign(
			signer,
			[]string{"test-audience"},
			"test-subject",
			true,
			time.Now(), time.Now().Add(time.Hour),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeTrue())
		Expect(result.Subject).To(Equal("test-subject"))
	})

	It("audience should fail", func() {
		token, err := jwt.Sign(
			signer,
			[]string{"not-audience"},
			"test-subject",
			false,
			time.Now(), time.Now().Add(time.Hour),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(Equal(jwt.ErrTokenInvalidAudience))
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("test-subject"))
	})

	It("token not valid yet", func() {
		token, err := jwt.Sign(
			signer,
			[]string{"test-audience"},
			"test-subject",
			false,
			time.Now().Add(time.Minute),
			time.Now().Add(time.Hour),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(Equal(jwt.ErrTokenTimeNotValid))
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("test-subject"))
	})

	It("token expired", func() {
		token, err := jwt.Sign(
			signer,
			[]string{"test-audience"},
			"test-subject",
			false,
			time.Now().Add(-1*time.Hour),
			time.Now().Add(-1*time.Minute),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(Equal(jwt.ErrTokenTimeNotValid))
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("test-subject"))
	})

	It("garbage token", func() {
		result, err := verifier.Verify([]byte("garbage"))
		Expect(err).To(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("test-subject"))
	})

	It("valid jwt structure, garbage token", func() {
		result, err := verifier.Verify([]byte("Z2FyYmFnZQ==.Z2FyYmFnZQ==.Z2FyYmFnZQ=="))
		Expect(err).To(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("test-subject"))
	})

	It("valid jwt structure, valid json, garbage token", func() {
		result, err := verifier.Verify([]byte("e30=.e30=.e30="))
		Expect(err).To(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("test-subject"))
	})

	It("valid jwt, invalid signing", func() {
		result, err := verifier.Verify([]byte(
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I" +
				"kpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
				"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"))
		Expect(err).To(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("test-subject"))
	})
})
