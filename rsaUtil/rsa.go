package rsaUtil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/go-tron/crypto/encoding"
)

func Encrypt(plainText string, key *rsa.PublicKey, encoding encoding.Encoding) (string, error) {
	cipherByte, err := rsa.EncryptPKCS1v15(rand.Reader, key, []byte(plainText))
	if err != nil {
		return "", err
	}
	cipherText := encoding.EncodeToString(cipherByte)
	return cipherText, nil
}

func Decrypt(cipherText string, key *rsa.PrivateKey, encoding encoding.Encoding) (string, error) {
	cipherByte, err := encoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	plainByte, err := rsa.DecryptPKCS1v15(rand.Reader, key, cipherByte)
	if err != nil {
		return "", err
	}
	plainText := string(plainByte)
	return plainText, nil
}

func Sign(msg string, key *rsa.PrivateKey, h crypto.Hash, encoding encoding.Encoding) (string, error) {
	hashMethod := h.New()
	hashMethod.Write([]byte(msg))
	bytes := hashMethod.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, key, h, bytes)
	if err != nil {
		return "", err
	}
	return encoding.EncodeToString(sign), nil
}

func Verify(msg string, sign string, key *rsa.PublicKey, h crypto.Hash, encoding encoding.Encoding) error {
	signBytes, err := encoding.DecodeString(sign)
	if err != nil {
		return err
	}
	hashMethod := h.New()
	hashMethod.Write([]byte(msg))
	bytes := hashMethod.Sum(nil)
	return rsa.VerifyPKCS1v15(key, h, bytes, signBytes)
}
