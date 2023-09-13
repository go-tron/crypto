package encoding

import (
	"encoding/base64"
	"encoding/hex"
)

type Encoding interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

type Hex struct {
}

func (*Hex) EncodeToString(src []byte) string {
	return hex.EncodeToString(src)
}
func (*Hex) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

type Base64 struct {
}

func (*Base64) EncodeToString(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}
func (*Base64) DecodeString(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
