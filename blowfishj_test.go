package blowfishj

import (
	"testing"
)

var fixtures = []struct {
	secret    string
	text      string
	encrypted string
}{
	{
		secret:    "foobar",
		text:      "How I wish I could recollect PI easily using one trick?",
		encrypted: "5D09840C5A0E7A196D949FC41012E27913C5E752AF38136C5ABDD2603B7F2A92198983B6DB7098C063E08D0AECA2891423FBAE3DE636A2",
	},
	{
		secret:    "密碼",
		text:      "一二三四 one two 3 4",
		encrypted: "4EF013DD039DDE30EAF13E04E17F21039C77760C3DADE16C",
	},
}

func TestEncrypt(t *testing.T) {
	for _, fixture := range fixtures {
		got, err := Encrypt(fixture.secret, fixture.text)
		if err != nil {
			t.Error("encrypt failed:", err)
		}
		if got != fixture.encrypted {
			t.Error("invalid encrypted text")
		}
	}
}

func TestDecrypt(t *testing.T) {
	for _, fixture := range fixtures {
		got, err := Decrypt(fixture.secret, fixture.encrypted)
		if err != nil {
			t.Error("decrypt failed:", err)
		}
		if got != fixture.text {
			t.Error("invalid decrypted text")
		}
	}
}
