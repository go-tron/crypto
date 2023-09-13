package aesUtil

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/go-tron/crypto/padding"
)

func ECBDecrypt(src, hexKey string) (r string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New(fmt.Sprint(e))
		}
	}()

	if src == "" {
		return "", errors.New("empty string")
	}

	cipherText, err := hex.DecodeString(src)
	if err != nil {
		return "", err
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockMode := NewECBDecrypter(block)
	plainText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainText, cipherText)
	plainText = padding.PKCS5UnPadding(plainText)
	return string(plainText), nil
}

func ECBEncrypt(src, hexKey string) (r string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New(fmt.Sprint(e))
		}
	}()

	if src == "" {
		return "", errors.New("empty string")
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockMode := NewECBEncrypter(block)
	plainText := []byte(src)
	plainText = padding.PKCS5Padding(plainText, block.BlockSize())
	cipherText := make([]byte, len(plainText))
	blockMode.CryptBlocks(cipherText, plainText)
	return hex.EncodeToString(cipherText), nil
}
