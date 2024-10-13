package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

func KeyDerive(k, h []byte, d string) (cipher.Stream, hash.Hash) {
	var iv, key, macKey = make([]byte, aes.BlockSize), make([]byte, 32), make([]byte, 32)
	generateKey(k, h, d[0], iv)
	generateKey(k, h, d[1], key)
	generateKey(k, h, d[2], macKey)
	var block, _ = aes.NewCipher(key)
	return cipher.NewCTR(block, iv), hmac.New(sha256.New, macKey)
}
func generateKey(k, h []byte, d byte, out []byte) {
	var keySoFar []byte
	var sha = sha256.New()
	for len(out) > 0 {
		sha.Reset()
		sha.Write(k)
		sha.Write(h)
		if len(keySoFar) == 0 {
			sha.Write([]byte{d})
			sha.Write(h)
		} else {
			sha.Write(keySoFar)
		}
		var digest = sha.Sum(nil)
		var n = copy(out, digest)
		out = out[n:]
		if len(out) > 0 {
			keySoFar = append(keySoFar, digest...)
		}
	}
}

type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) { copy(dst, src) }
