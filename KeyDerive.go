package tunnel

import (
	"crypto/aes"
	"crypto/sha256"
)

func KeyDerive(k, h []byte, d string) (key []byte, iv []byte, macKey []byte) {
	iv, key, macKey = make([]byte, aes.BlockSize), make([]byte, 32), make([]byte, 32)
	generate(k, h, d[0], iv)
	generate(k, h, d[1], key)
	generate(k, h, d[2], macKey)
	return
}
func generate(k, h []byte, d byte, out []byte) {
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
