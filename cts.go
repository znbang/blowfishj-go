package blowfishj

import "github.com/c0mm4nd/go-ripemd"

type blowfishCTS struct {
	ecb blowfishECB

	feedback []byte
}

func (cts *blowfishCTS) initialize(key []byte) error {
	cts.feedback = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	hash := ripemd.New256()
	_, err := hash.Write(key)
	if err != nil {
		return err
	}
	hashedKey := hash.Sum(nil)
	cts.ecb.initialize(hashedKey, 0, len(hashedKey))
	cts.ecb.encrypt(cts.feedback, 0, cts.feedback, 0, len(cts.feedback))

	backupFeedback := make([]byte, len(cts.feedback))
	copy(backupFeedback, cts.feedback)
	cts.encrypt(hashedKey, 0, hashedKey, 0, len(hashedKey))
	copy(cts.feedback, backupFeedback)

	return nil
}

func (cts *blowfishCTS) encrypt(inbuf []byte, inpos int, outbuf []byte, outpos int, len int) int {
	buf := make([]byte, blockSize)
	for offset := 0; len-offset >= 8; offset += blockSize {
		xorBuffers(cts.feedback, blockSize, inbuf, inpos+offset, buf, 0)
		cts.ecb.encrypt(buf, 0, outbuf, outpos+offset, blockSize)
		xorBuffers(cts.feedback, blockSize, outbuf, outpos+offset, cts.feedback, 0)
	}
	if len%blockSize > 0 {
		nleft := len % blockSize
		offset := len - nleft
		copy(buf, cts.feedback)
		cts.ecb.encrypt(buf, 0, buf, 0, blockSize)
		xorBuffers(buf, nleft, inbuf, offset, outbuf, offset)
		xorBuffers(cts.feedback, blockSize, buf, 0, cts.feedback, 0)
	}
	return len
}

func (cts *blowfishCTS) decrypt(inbuf []byte, inpos int, outbuf []byte, outpos int, len int) int {
	buf := make([]byte, blockSize)
	copy(outbuf, inbuf)
	for offset := 0; len-offset >= 8; offset += blockSize {
		xorBuffers(cts.feedback, blockSize, outbuf, outpos+offset, buf, 0)
		cts.ecb.decrypt(inbuf, inpos+offset, outbuf, outpos+offset, blockSize)
		xorBuffers(cts.feedback, blockSize, outbuf, outpos+offset, outbuf, outpos+offset)
		copy(cts.feedback, buf)
	}
	if len%blockSize > 0 {
		nleft := len % blockSize
		offset := len - nleft
		copy(buf, cts.feedback)
		cts.ecb.encrypt(buf, 0, buf, 0, blockSize)
		xorBuffers(buf, nleft, inbuf, offset, outbuf, offset)
		xorBuffers(cts.feedback, blockSize, buf, 0, cts.feedback, 0)
	}
	return len
}
