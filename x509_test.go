package jwt_test

import (
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"os"

	"github.com/na4ma4/jwt/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("x509 File Operations", func() {
	It("should succeed, public key from afs", func() {
		publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(createAfs(), "cert.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(publicKey).To(BeAssignableToTypeOf(&rsa.PublicKey{}))
	})

	It("should succeed, private key from afs", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(privateKey).To(BeAssignableToTypeOf(&rsa.PrivateKey{}))
	})

	It("should fail, public key from afs, invalid file", func() {
		publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(createAfs(), "cert2.pem")
		e := &os.PathError{}
		Expect(errors.As(err, &e)).To(BeTrue())
		Expect(e).NotTo(BeNil())
		Expect(publicKey).To(BeNil())
	})

	It("should fail, private key from afs, invalid file", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key2.pem")
		e := &os.PathError{}
		Expect(errors.As(err, &e)).To(BeTrue())
		Expect(e).NotTo(BeNil())
		Expect(privateKey).To(BeNil())
	})

	It("should fail, public key from afs, loading wrong type", func() {
		publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).To(MatchError("unable to parse certificate: x509: malformed tbs certificate"))
		Expect(publicKey).To(BeNil())
	})

	//nolint:lll // long error match
	It("should fail, private key from afs, loading wrong type", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "cert.pem")
		Expect(err).To(MatchError(asn1.StructuralError{Msg: "tags don't match (2 vs {class:0 tag:16 length:400 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} int @4"}))
		Expect(privateKey).To(BeNil())
	})
})
