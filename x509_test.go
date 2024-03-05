package jwt_test

import (
	"encoding/asn1"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/na4ma4/jwt/v2"
)

func TestX509FileOperations_Succeed_PublicKeyFromAFS(t *testing.T) {
	publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(createAfs(), "cert.pem")
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if v := reflect.TypeOf(publicKey).String(); v != "*rsa.PublicKey" {
		t.Errorf("expected publicKey to be type(%s), received type(%s)", "*rsa.PublicKey", v)
	}
}

func TestX509FileOperations_Succeed_PrivateKeyFromAFS(t *testing.T) {
	privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if v := reflect.TypeOf(privateKey).String(); v != "*rsa.PrivateKey" {
		t.Errorf("expected privateKey to be type(%s), received type(%s)", "*rsa.PrivateKey", v)
	}
}

func TestX509FileOperations_Fail_PublicKeyFromAFS_InvalidFile(t *testing.T) {
	publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(createAfs(), "cert2.pem")
	if os.IsNotExist(err) {
		t.Errorf("expected error to be of type os.PathError: %v", err)
	}
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}
	if publicKey != nil {
		t.Error("expected publicKey to be bil, but returned non-nil")
	}
}

func TestX509FileOperations_Fail_PrivateKeyFromAFS_InvalidFile(t *testing.T) {
	privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key2.pem")
	if os.IsNotExist(err) {
		t.Errorf("expected error to be of type os.PathError: %v", err)
	}
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}

	if privateKey != nil {
		t.Error("expected privateKey to be bil, but returned non-nil")
	}
}

func TestX509FileOperations_Fail_PublicKeyFromAFS_FileWrongType(t *testing.T) {
	publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(createAfs(), "key.pem")
	if !strings.Contains(err.Error(), "unable to parse certificate: x509: malformed tbs certificate") {
		t.Errorf(
			"expected error to contain '%s', returned '%s'",
			"unable to parse certificate: x509: malformed tbs certificate",
			err,
		)
	}
	if publicKey != nil {
		t.Error("expected publicKey to be bil, but returned non-nil")
	}
}

func TestX509FileOperations_Fail_PrivateKeyFromAFS_FileWrongType(t *testing.T) {
	errorMsg := "tags don't match (2 vs {class:0 tag:16 length:400 isCompound:true}) {optional:false explicit:false " +
		"application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} " +
		"int @4"
	privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "cert.pem")
	targetErr := &asn1.StructuralError{}
	if errors.As(err, targetErr) {
		if !strings.Contains(targetErr.Msg, errorMsg) {
			t.Errorf("expected error to contain '%s', returned '%s'", errorMsg, targetErr.Msg)
		}
	} else {
		t.Errorf("expected error to be of type 'asn1.StructuralError', returned '%s'", err)
	}
	if !strings.Contains(err.Error(), errorMsg) {
		t.Errorf("expected error to contain '%s', returned '%s'", errorMsg, err)
	}
	if privateKey != nil {
		t.Error("expected privateKey to be bil, but returned non-nil")
	}
}
