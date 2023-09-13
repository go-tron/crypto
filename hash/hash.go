package hash

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"github.com/go-tron/crypto/encoding"
)

func Byte(str string, h crypto.Hash) []byte {
	hashMethod := h.New()
	hashMethod.Write([]byte(str))
	return hashMethod.Sum(nil)
}

func Hex(str string, h crypto.Hash) string {
	hashMethod := h.New()
	hashMethod.Write([]byte(str))
	return (&encoding.Hex{}).EncodeToString(hashMethod.Sum(nil))
}

func Base64(str string, h crypto.Hash) string {
	hashMethod := h.New()
	hashMethod.Write([]byte(str))
	return (&encoding.Base64{}).EncodeToString(hashMethod.Sum(nil))
}
