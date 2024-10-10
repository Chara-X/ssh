package ssh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/ssh"
)

type StreamPacketCipher struct {
	cipher cipher.Stream
	mac    hash.Hash
	seqNum uint32
}

func NewStreamPacketCipher(secret, sessionID []byte, dir string) *StreamPacketCipher {
	var iv, key, macKey = make([]byte, aes.BlockSize), make([]byte, 32), make([]byte, 32)
	generateKey(secret, sessionID, dir[0], iv)
	generateKey(secret, sessionID, dir[1], key)
	generateKey(secret, sessionID, dir[2], macKey)
	var block, _ = aes.NewCipher(key)
	return &StreamPacketCipher{
		cipher: cipher.NewCTR(block, iv),
		mac:    hmac.New(sha256.New, macKey),
	}
}
func (s *StreamPacketCipher) ReadCipherPacket(r io.Reader, msg interface{}) error {
	var header = make([]byte, 5)
	r.Read(header)
	s.cipher.XORKeyStream(header, header)
	var length = binary.BigEndian.Uint32(header[:4])
	fmt.Println("length:", length)
	var paddingLength = uint32(header[4])
	fmt.Println("paddingLength:", paddingLength)
	var body = make([]byte, length-1)
	r.Read(body)
	s.cipher.XORKeyStream(body, body)
	fmt.Println("body:", body)
	var mac = make([]byte, 32)
	r.Read(mac)
	fmt.Println("mac:", mac)
	s.mac.Reset()
	binary.Write(s.mac, binary.BigEndian, s.seqNum)
	s.mac.Write(header)
	s.mac.Write(body)
	if subtle.ConstantTimeCompare(s.mac.Sum(nil), mac) == 0 {
		panic("ssh: MAC failure")
	}
	ssh.Unmarshal(body[:length-1-paddingLength], msg)
	s.seqNum++
	return nil
}
func (s *StreamPacketCipher) WriteCipherPacket(w io.Writer, msg interface{}) error {
	var payload = ssh.Marshal(msg)
	var paddingLength = aes.BlockSize - (5+len(payload))%aes.BlockSize
	if paddingLength < 4 {
		paddingLength += aes.BlockSize
	}
	var length = 1 + len(payload) + paddingLength
	var header = make([]byte, 5)
	binary.BigEndian.PutUint32(header[:4], uint32(length))
	header[4] = byte(paddingLength)
	var padding = make([]byte, paddingLength)
	rand.Reader.Read(padding)
	s.mac.Reset()
	var seqNumBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(seqNumBytes, s.seqNum)
	s.mac.Write(seqNumBytes)
	s.mac.Write(header)
	s.mac.Write(payload)
	s.mac.Write(padding)
	var mac = s.mac.Sum(nil)
	s.cipher.XORKeyStream(header, header)
	s.cipher.XORKeyStream(payload, payload)
	s.cipher.XORKeyStream(padding, padding)
	w.Write(header)
	w.Write(payload)
	w.Write(padding)
	w.Write(mac)
	s.seqNum++
	return nil
}
func generateKey(k, h []byte, d byte, out []byte) {
	var keySoFar []byte
	var sha = sha256.New()
	for len(out) > 0 {
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
