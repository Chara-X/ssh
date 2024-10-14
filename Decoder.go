package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"io"
	"reflect"

	"github.com/Chara-X/tunnel/msg"
	"golang.org/x/crypto/ssh"
)

type Decoder struct {
	r      io.Reader
	cipher cipher.Stream
	mac    hash.Hash
	seq    uint32
}

func NewDecoder(r io.Reader) *Decoder { return &Decoder{r: r, cipher: noneCipher{}} }
func (d *Decoder) SetCipher(key, iv, macKey []byte) {
	var block, _ = aes.NewCipher(key)
	d.cipher = cipher.NewCTR(block, iv)
	d.mac = hmac.New(sha256.New, macKey)
}
func (d *Decoder) Decode() interface{} {
	var header = make([]byte, 5)
	d.r.Read(header)
	d.cipher.XORKeyStream(header, header)
	var length, tailerLen = binary.BigEndian.Uint32(header[0:4]), uint32(header[4])
	var body = make([]byte, length-1-tailerLen)
	d.r.Read(body)
	d.cipher.XORKeyStream(body, body)
	var tailer = make([]byte, tailerLen)
	d.r.Read(tailer)
	d.cipher.XORKeyStream(tailer, tailer)
	if d.mac != nil {
		var mac = make([]byte, d.mac.Size())
		d.r.Read(mac)
		d.mac.Reset()
		binary.Write(d.mac, binary.BigEndian, d.seq)
		d.mac.Write(header)
		d.mac.Write(body)
		d.mac.Write(tailer)
		if subtle.ConstantTimeCompare(d.mac.Sum(nil), mac) != 1 {
			panic("MAC failure")
		}
	}
	d.seq++
	var v = reflect.New(msg.TypeMapper[body[0]]).Interface()
	ssh.Unmarshal(body, v)
	return v
}
