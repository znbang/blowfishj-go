package blowfishj

import (
	"encoding/hex"
	"strings"
)

func Encrypt(key string, src string) (string, error) {
	buf := []byte(src)
	cts := blowfishCTS{}
	if err := cts.initialize([]byte(key)); err != nil {
		return "", err
	}
	cts.encrypt(buf, 0, buf, 0, len(buf))
	return strings.ToUpper(hex.EncodeToString(buf)), nil
}

func Decrypt(key string, src string) (string, error) {
	buf, err := hex.DecodeString(src)
	if err != nil {
		return "", err
	}
	cts := blowfishCTS{}
	if err = cts.initialize([]byte(key)); err != nil {
		return "", err
	}
	cts.decrypt(buf, 0, buf, 0, len(buf))
	return string(buf), nil
}
