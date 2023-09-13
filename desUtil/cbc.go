package desUtil

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
	"fmt"
	"github.com/go-tron/crypto/padding"
)

func EncryptCBC_ZerosPadding(src, key []byte) (cipherText []byte, err error) {
	return EncryptCBC(src, key, padding.ZEROS_PADDING)
}
func EncryptCBC_PKCS5Padding(src, key []byte) (cipherText []byte, err error) {
	return EncryptCBC(src, key, padding.PKCS5_PADDING)
}
func DecryptCBC_ZerosPadding(src, key []byte) (cipherText []byte, err error) {
	return DecryptCBC(src, key, padding.ZEROS_PADDING)
}
func DecryptCBC_PKCS5Padding(src, key []byte) (cipherText []byte, err error) {
	return DecryptCBC(src, key, padding.PKCS5_PADDING)
}

func EncryptCBC(src, key []byte, padstr string) (cipherText []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New(fmt.Sprint(e))
		}
	}()

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src = padding.Padding(padstr, src, block.BlockSize())
	iv := make([]byte, block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, iv)
	cipherText = make([]byte, len(src))
	mode.CryptBlocks(cipherText, src)
	return cipherText, nil
}

func DecryptCBC(src, key []byte, padstr string) (plainText []byte, err error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, block.BlockSize())
	mode := cipher.NewCBCDecrypter(block, iv)
	plainText = make([]byte, len(src))
	mode.CryptBlocks(plainText, src)

	plainText = padding.UnPadding(padstr, plainText)
	return plainText, nil
}
