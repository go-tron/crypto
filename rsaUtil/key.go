package rsaUtil

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"
)

func GetPublicKeyFromCertificate(cer []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(cer)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	return cert.PublicKey.(*rsa.PublicKey), nil
}

func GetPublicKeyFile(file string) (*rsa.PublicKey, error) {
	pem, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return GetPublicKeyPem(pem)
}

func GetPublicKeyPem(publicKey []byte) (*rsa.PublicKey, error) {
	var buffer bytes.Buffer
	if !strings.HasPrefix(string(publicKey), "-----BEGIN") {
		buffer.Write([]byte("-----BEGIN PUBLIC KEY-----\n"))
	}
	buffer.Write(publicKey)
	if !strings.HasSuffix(string(publicKey), "KEY-----") {
		buffer.Write([]byte("\n-----END PUBLIC KEY-----"))
	}
	block, _ := pem.Decode(buffer.Bytes())
	if block == nil {
		return nil, errors.New("get public key error")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), err
}

func GetPrivateKeyFile(file string) (*rsa.PrivateKey, error) {
	pem, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return GetPrivateKeyPem(pem)
}

func GetPrivateKeyPem(privateKey []byte) (*rsa.PrivateKey, error) {
	var buffer bytes.Buffer
	if !strings.HasPrefix(string(privateKey), "-----BEGIN") {
		buffer.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\n"))
	}
	buffer.Write(privateKey)
	if !strings.HasSuffix(string(privateKey), "KEY-----") {
		buffer.Write([]byte("\n-----END RSA PRIVATE KEY-----"))
	}
	block, _ := pem.Decode(buffer.Bytes())
	if block == nil {
		return nil, errors.New("get private key error")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}
	pri2, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pri2.(*rsa.PrivateKey), nil
}
