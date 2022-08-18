package blowfishj

type blowfishECB struct {
	pbox     []int32
	sbox1    []int32
	sbox2    []int32
	sbox3    []int32
	sbox4    []int32
	blockBuf []uint8
	weakKey  int
}

func copyArrayUint32ToInt32(src []uint32, dst []int32) {
	for i, v := range src {
		dst[i] = int32(v)
	}
}

func byteArrayToInt(buf []byte, ofs int) int32 {
	return int32(buf[ofs])<<24 | int32((buf[ofs+1])&0x0ff)<<16 | int32((buf[ofs+2])&0x0ff)<<8 | int32(buf[ofs+3])&0x0ff

}

func xorBuffers(data []byte, len int, src []byte, srcOffset int, dst []byte, dstOffset int) {
	for i := 0; i < len; i++ {
		dst[i+dstOffset] = (src[i+srcOffset] ^ data[i]) & 0xff
	}
}

func (ecb *blowfishECB) initialize(key []byte, ofs int, len int) {
	ecb.pbox = make([]int32, pboxEntries)
	ecb.sbox1 = make([]int32, sboxEntries)
	ecb.sbox2 = make([]int32, sboxEntries)
	ecb.sbox3 = make([]int32, sboxEntries)
	ecb.sbox4 = make([]int32, sboxEntries)
	ecb.blockBuf = make([]byte, blockSize)

	copyArrayUint32ToInt32(pboxInit, ecb.pbox)
	copyArrayUint32ToInt32(sbox1Init, ecb.sbox1)
	copyArrayUint32ToInt32(sbox2Init, ecb.sbox2)
	copyArrayUint32ToInt32(sbox3Init, ecb.sbox3)
	copyArrayUint32ToInt32(sbox4Init, ecb.sbox4)

	if len == 0 {
		return
	}

	var build int32
	ofsBak := ofs
	end := ofs + len

	for i := 0; i < pboxEntries; i++ {
		for j := 0; j < 4; j++ {
			build = (build << 8) | int32(key[ofs]&0x0ff)

			ofs++

			if ofs == end {
				ofs = ofsBak
			}
		}
		ecb.pbox[i] ^= build
	}

	for i := 0; i < blockSize; i++ {
		ecb.blockBuf[i] = 0
	}

	for i := 0; i < pboxEntries; {
		ecb.encryptPrv(ecb.blockBuf, 0, ecb.blockBuf, 0, blockSize)
		ecb.pbox[i] = byteArrayToInt(ecb.blockBuf, 0)
		i++
		ecb.pbox[i] = byteArrayToInt(ecb.blockBuf, 4)
		i++
	}

	for i := 0; i < sboxEntries; {
		ecb.encryptPrv(ecb.blockBuf, 0, ecb.blockBuf, 0, blockSize)
		ecb.sbox1[i] = byteArrayToInt(ecb.blockBuf, 0)
		i++
		ecb.sbox1[i] = byteArrayToInt(ecb.blockBuf, 4)
		i++
	}

	for i := 0; i < sboxEntries; {
		ecb.encryptPrv(ecb.blockBuf, 0, ecb.blockBuf, 0, blockSize)
		ecb.sbox2[i] = byteArrayToInt(ecb.blockBuf, 0)
		i++
		ecb.sbox2[i] = byteArrayToInt(ecb.blockBuf, 4)
		i++
	}

	for i := 0; i < sboxEntries; {
		ecb.encryptPrv(ecb.blockBuf, 0, ecb.blockBuf, 0, blockSize)
		ecb.sbox3[i] = byteArrayToInt(ecb.blockBuf, 0)
		i++
		ecb.sbox3[i] = byteArrayToInt(ecb.blockBuf, 4)
		i++
	}

	for i := 0; i < sboxEntries; {
		ecb.encryptPrv(ecb.blockBuf, 0, ecb.blockBuf, 0, blockSize)
		ecb.sbox4[i] = byteArrayToInt(ecb.blockBuf, 0)
		i++
		ecb.sbox4[i] = byteArrayToInt(ecb.blockBuf, 4)
		i++
	}

	ecb.weakKey = -1
}

func (ecb *blowfishECB) encrypt(inbuf []byte, inpos int, outbuf []byte, outpos int, len int) int {
	return ecb.encryptPrv(inbuf, inpos, outbuf, outpos, len)
}

func (ecb *blowfishECB) encryptPrv(inbuf []byte, inpos int, outbuf []byte, outpos int, len int) int {
	len -= len % blockSize

	c := inpos + len

	pbox := ecb.pbox
	pbox00 := pbox[0]
	pbox01 := pbox[1]
	pbox02 := pbox[2]
	pbox03 := pbox[3]
	pbox04 := pbox[4]
	pbox05 := pbox[5]
	pbox06 := pbox[6]
	pbox07 := pbox[7]
	pbox08 := pbox[8]
	pbox09 := pbox[9]
	pbox10 := pbox[10]
	pbox11 := pbox[11]
	pbox12 := pbox[12]
	pbox13 := pbox[13]
	pbox14 := pbox[14]
	pbox15 := pbox[15]
	pbox16 := pbox[16]
	pbox17 := pbox[17]

	sbox1 := ecb.sbox1
	sbox2 := ecb.sbox2
	sbox3 := ecb.sbox3
	sbox4 := ecb.sbox4

	var (
		hi int32
		lo int32
	)

	for inpos < c {
		hi = int32(inbuf[inpos]) << 24
		inpos++
		hi |= int32(inbuf[inpos]) << 16 & 0x0ff0000
		inpos++
		hi |= int32(inbuf[inpos]) << 8 & 0x000ff00
		inpos++
		hi |= int32(inbuf[inpos]) & 0x00000ff
		inpos++

		lo = int32(inbuf[inpos]) << 24
		inpos++
		lo |= int32(inbuf[inpos]) << 16 & 0x0ff0000
		inpos++
		lo |= int32(inbuf[inpos]) << 8 & 0x000ff00
		inpos++
		lo |= int32(inbuf[inpos]) & 0x00000ff
		inpos++

		hi ^= pbox00
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox01
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox02
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox03
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox04
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox05
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox06
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox07
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox08
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox09
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox10
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox11
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox12
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox13
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox14
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox15
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox16

		lo ^= pbox17

		outbuf[outpos] = byte(uint32(lo) >> 24)
		outpos++
		outbuf[outpos] = byte(uint32(lo) >> 16)
		outpos++
		outbuf[outpos] = byte(uint32(lo) >> 8)
		outpos++
		outbuf[outpos] = byte(lo)
		outpos++

		outbuf[outpos] = byte(uint32(hi) >> 24)
		outpos++
		outbuf[outpos] = byte(uint32(hi) >> 16)
		outpos++
		outbuf[outpos] = byte(uint32(hi) >> 8)
		outpos++
		outbuf[outpos] = byte(hi)
		outpos++
	}

	return len
}

func (ecb *blowfishECB) decrypt(inbuf []byte, inpos int, outbuf []byte, outpos int, len int) int {
	len -= len % blockSize

	c := inpos + len

	pbox := ecb.pbox
	pbox00 := pbox[0]
	pbox01 := pbox[1]
	pbox02 := pbox[2]
	pbox03 := pbox[3]
	pbox04 := pbox[4]
	pbox05 := pbox[5]
	pbox06 := pbox[6]
	pbox07 := pbox[7]
	pbox08 := pbox[8]
	pbox09 := pbox[9]
	pbox10 := pbox[10]
	pbox11 := pbox[11]
	pbox12 := pbox[12]
	pbox13 := pbox[13]
	pbox14 := pbox[14]
	pbox15 := pbox[15]
	pbox16 := pbox[16]
	pbox17 := pbox[17]

	sbox1 := ecb.sbox1
	sbox2 := ecb.sbox2
	sbox3 := ecb.sbox3
	sbox4 := ecb.sbox4

	var (
		hi int32
		lo int32
	)

	for inpos < c {
		hi = int32(inbuf[inpos]) << 24
		inpos++
		hi |= int32(inbuf[inpos]) << 16 & 0x0ff0000
		inpos++
		hi |= int32(inbuf[inpos]) << 8 & 0x000ff00
		inpos++
		hi |= int32(inbuf[inpos]) & 0x00000ff
		inpos++

		lo = int32(inbuf[inpos]) << 24
		inpos++
		lo |= int32(inbuf[inpos]) << 16 & 0x0ff0000
		inpos++
		lo |= int32(inbuf[inpos]) << 8 & 0x000ff00
		inpos++
		lo |= int32(inbuf[inpos]) & 0x00000ff
		inpos++

		hi ^= pbox17
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox16
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox15
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox14
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox13
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox12
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox11
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox10
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox09
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox08
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox07
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox06
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox05
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox04
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox03
		lo ^= (((sbox1[uint32(hi)>>24] + sbox2[(uint32(hi)>>16)&0x0ff]) ^ sbox3[(uint32(hi)>>8)&0x0ff]) + sbox4[hi&0x0ff]) ^ pbox02
		hi ^= (((sbox1[uint32(lo)>>24] + sbox2[(uint32(lo)>>16)&0x0ff]) ^ sbox3[(uint32(lo)>>8)&0x0ff]) + sbox4[lo&0x0ff]) ^ pbox01

		lo ^= pbox00

		outbuf[outpos] = byte(uint32(lo) >> 24)
		outpos++
		outbuf[outpos] = byte(uint32(lo) >> 16)
		outpos++
		outbuf[outpos] = byte(uint32(lo) >> 8)
		outpos++
		outbuf[outpos] = byte(lo)
		outpos++

		outbuf[outpos] = byte(uint32(hi) >> 24)
		outpos++
		outbuf[outpos] = byte(uint32(hi) >> 16)
		outpos++
		outbuf[outpos] = byte(uint32(hi) >> 8)
		outpos++
		outbuf[outpos] = byte(hi)
		outpos++
	}

	return len
}
