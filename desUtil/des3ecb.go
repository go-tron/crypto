package desUtil

import "github.com/forgoer/openssl"

func Des3ECBEncrypt(src, key []byte, padding string) ([]byte, error) {
	return openssl.Des3ECBEncrypt(src, key, padding)
}

func Des3ECBDecrypt(src, key []byte, padding string) ([]byte, error) {
	return openssl.Des3ECBDecrypt(src, key, padding)
}
