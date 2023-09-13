package desUtil

import "github.com/forgoer/openssl"

func Des3CBCEncrypt(src, key []byte, iv []byte, padding string) ([]byte, error) {
	return openssl.Des3CBCEncrypt(src, key, iv, padding)
}

func Des3CBCDecrypt(src, key []byte, iv []byte, padding string) ([]byte, error) {
	return openssl.Des3CBCDecrypt(src, key, iv, padding)
}
