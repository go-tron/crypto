package desUtil

import (
	"encoding/base64"
	"fmt"
	"github.com/forgoer/openssl"
	"testing"
)

func TestEncrypt(t *testing.T) {

	var a = "170"
	var key = "189181608651831936957625"
	var iv = "87654321"

	ret, err := openssl.Des3CBCEncrypt([]byte(a), []byte(key), []byte(iv), openssl.PKCS5_PADDING)
	if err != nil {
		fmt.Println(err)
		return
	}

	src := base64.StdEncoding.EncodeToString(ret)

	fmt.Println("src", src)
}

func TestDecrypt(t *testing.T) {

	var a = "wwHyn6Eu8V8="
	var key = "189181608651831936957625"
	var iv = "87654321"

	src, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		fmt.Println(err)
		return
	}

	ret, err := openssl.Des3CBCDecrypt(src, []byte(key), []byte(iv), openssl.PKCS5_PADDING)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("ret", string(ret))
}
