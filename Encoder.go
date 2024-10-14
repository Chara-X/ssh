package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/ssh"
)

type Encoder struct {
	w      io.Writer
	cipher cipher.Stream
	mac    hash.Hash
	seq    uint32
}

func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w, cipher: noneCipher{}} }
func (e *Encoder) SetCipher(key, iv, macKey []byte) {
	var block, _ = aes.NewCipher(key)
	e.cipher = cipher.NewCTR(block, iv)
	e.mac = hmac.New(sha256.New, macKey)
}
func (e *Encoder) Encode(v interface{}) {
	var body = ssh.Marshal(v)
	var tailerLen = aes.BlockSize - (5+len(body))%aes.BlockSize
	if tailerLen < 4 {
		tailerLen += aes.BlockSize
	}
	var length = len(body) + 1 + tailerLen
	var header = make([]byte, 5)
	binary.BigEndian.PutUint32(header, uint32(length))
	header[4] = byte(tailerLen)
	var tailer = make([]byte, tailerLen)
	rand.Reader.Read(tailer)
	if e.mac != nil {
		e.mac.Reset()
		binary.Write(e.mac, binary.BigEndian, e.seq)
		e.mac.Write(header)
		e.mac.Write(body)
		e.mac.Write(tailer)
	}
	e.cipher.XORKeyStream(header, header)
	e.cipher.XORKeyStream(body, body)
	e.cipher.XORKeyStream(tailer, tailer)
	e.w.Write(header)
	e.w.Write(body)
	e.w.Write(tailer)
	if e.mac != nil {
		e.w.Write(e.mac.Sum(nil))
	}
	e.seq++
}
