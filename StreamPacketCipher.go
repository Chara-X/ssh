package ssh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

const prefixLen = 5
const packetSizeMultiple = 16
const maxPacket = 256 * 1024
const msgDisconnect = 1

type disconnectMsg struct {
	Reason   uint32 `sshtype:"1"`
	Message  string
	Language string
}

// StreamPacketCipher is a packetCipher using a stream cipher.
type StreamPacketCipher struct {
	mac    hash.Hash
	cipher cipher.Stream
	etm    bool
	// The following members are to avoid per-packet allocations.
	prefix      [prefixLen]byte
	seqNumBytes [4]byte
	padding     [2 * packetSizeMultiple]byte
	packetData  []byte
	macResult   []byte
}

func NewStreamPacketCipher(dir string, kex *kexResult) *StreamPacketCipher {
	var iv, key, macKey = make([]byte, aes.BlockSize), make([]byte, 32), make([]byte, 32)
	generateKeyMaterial(iv, []byte{dir[0]}, kex)
	generateKeyMaterial(key, []byte{dir[1]}, kex)
	generateKeyMaterial(macKey, []byte{dir[2]}, kex)
	var block, err = aes.NewCipher(key)
	fmt.Println(err)
	return &StreamPacketCipher{
		cipher:    cipher.NewCTR(block, iv),
		mac:       hmac.New(sha256.New, macKey),
		etm:       false,
		macResult: make([]byte, 32),
	}
}

// readCipherPacket reads and decrypt a single packet from the reader argument.
func (s *StreamPacketCipher) readCipherPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	if _, err := io.ReadFull(r, s.prefix[:]); err != nil {
		panic(err)
	}
	var encryptedPaddingLength [1]byte
	if s.mac != nil && s.etm {
		copy(encryptedPaddingLength[:], s.prefix[4:5])
		s.cipher.XORKeyStream(s.prefix[4:5], s.prefix[4:5])
	} else {
		s.cipher.XORKeyStream(s.prefix[:], s.prefix[:])
	}
	length := binary.BigEndian.Uint32(s.prefix[0:4])
	paddingLength := uint32(s.prefix[4])
	fmt.Println("length:", length)
	fmt.Println("paddingLength:", paddingLength)
	var macSize uint32
	if s.mac != nil {
		s.mac.Reset()
		binary.BigEndian.PutUint32(s.seqNumBytes[:], seqNum)
		s.mac.Write(s.seqNumBytes[:])
		if s.etm {
			s.mac.Write(s.prefix[:4])
			s.mac.Write(encryptedPaddingLength[:])
		} else {
			s.mac.Write(s.prefix[:])
		}
		macSize = uint32(s.mac.Size())
	}
	if length <= paddingLength+1 {
		return nil, errors.New("ssh: invalid packet length, packet too small")
	}
	if length > maxPacket {
		return nil, errors.New("ssh: invalid packet length, packet too large")
	}
	// the maxPacket check above ensures that length-1+macSize
	// does not overflow.
	if uint32(cap(s.packetData)) < length-1+macSize {
		s.packetData = make([]byte, length-1+macSize)
	} else {
		s.packetData = s.packetData[:length-1+macSize]
	}
	if _, err := io.ReadFull(r, s.packetData); err != nil {
		return nil, err
	}
	mac := s.packetData[length-1:]
	data := s.packetData[:length-1]
	if s.mac != nil && s.etm {
		s.mac.Write(data)
	}
	s.cipher.XORKeyStream(data, data)
	if s.mac != nil {
		if !s.etm {
			s.mac.Write(data)
		}
		s.macResult = s.mac.Sum(s.macResult[:0])
		if subtle.ConstantTimeCompare(s.macResult, mac) != 1 {
			return nil, errors.New("ssh: MAC failure")
		}
	}
	return s.packetData[:length-paddingLength-1], nil
}

// writeCipherPacket encrypts and sends a packet of data to the writer argument
func (s *StreamPacketCipher) writeCipherPacket(seqNum uint32, w io.Writer, rand io.Reader, packet []byte) error {
	if len(packet) > maxPacket {
		return errors.New("ssh: packet too large")
	}
	aadlen := 0
	if s.mac != nil && s.etm {
		// packet length is not encrypted for EtM modes
		aadlen = 4
	}
	paddingLength := packetSizeMultiple - (prefixLen+len(packet)-aadlen)%packetSizeMultiple
	if paddingLength < 4 {
		paddingLength += packetSizeMultiple
	}
	length := len(packet) + 1 + paddingLength
	binary.BigEndian.PutUint32(s.prefix[:], uint32(length))
	s.prefix[4] = byte(paddingLength)
	padding := s.padding[:paddingLength]
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}
	if s.mac != nil {
		s.mac.Reset()
		binary.BigEndian.PutUint32(s.seqNumBytes[:], seqNum)
		s.mac.Write(s.seqNumBytes[:])
		if s.etm {
			// For EtM algorithms, the packet length must stay unencrypted,
			// but the following data (padding length) must be encrypted
			s.cipher.XORKeyStream(s.prefix[4:5], s.prefix[4:5])
		}
		s.mac.Write(s.prefix[:])
		if !s.etm {
			// For non-EtM algorithms, the algorithm is applied on unencrypted data
			s.mac.Write(packet)
			s.mac.Write(padding)
		}
	}
	if !(s.mac != nil && s.etm) {
		// For EtM algorithms, the padding length has already been encrypted
		// and the packet length must remain unencrypted
		s.cipher.XORKeyStream(s.prefix[:], s.prefix[:])
	}
	s.cipher.XORKeyStream(packet, packet)
	s.cipher.XORKeyStream(padding, padding)
	if s.mac != nil && s.etm {
		// For EtM algorithms, packet and padding must be encrypted
		s.mac.Write(packet)
		s.mac.Write(padding)
	}
	if _, err := w.Write(s.prefix[:]); err != nil {
		return err
	}
	if _, err := w.Write(packet); err != nil {
		return err
	}
	if _, err := w.Write(padding); err != nil {
		return err
	}
	if s.mac != nil {
		s.macResult = s.mac.Sum(s.macResult[:0])
		if _, err := w.Write(s.macResult); err != nil {
			return err
		}
	}
	return nil
}

//	func (s *StreamPacketCipher) ReadCipherPacket(r io.Reader, msg interface{}) error {
//		var header = make([]byte, 5)
//		r.Read(header)
//		s.cipher.XORKeyStream(header, header)
//		var length = binary.BigEndian.Uint32(header[:4])
//		fmt.Println("length:", length)
//		var paddingLength = uint32(header[4])
//		fmt.Println("paddingLength:", paddingLength)
//		var body = make([]byte, length-1)
//		r.Read(body)
//		s.cipher.XORKeyStream(body, body)
//		fmt.Println("body:", body)
//		var mac = make([]byte, 32)
//		r.Read(mac)
//		fmt.Println("mac:", mac)
//		s.mac.Reset()
//		binary.Write(s.mac, binary.BigEndian, s.seqNum)
//		s.mac.Write(header)
//		s.mac.Write(body)
//		if subtle.ConstantTimeCompare(s.mac.Sum(nil), mac) == 0 {
//			panic("ssh: MAC failure")
//		}
//		ssh.Unmarshal(body[:length-1-paddingLength], msg)
//		s.seqNum++
//		return nil
//	}
//
//	func (s *StreamPacketCipher) WriteCipherPacket(w io.Writer, msg interface{}) error {
//		var payload = ssh.Marshal(msg)
//		var paddingLength = aes.BlockSize - (5+len(payload))%aes.BlockSize
//		if paddingLength < 4 {
//			paddingLength += aes.BlockSize
//		}
//		var length = 1 + len(payload) + paddingLength
//		var header = make([]byte, 5)
//		binary.BigEndian.PutUint32(header[:4], uint32(length))
//		header[4] = byte(paddingLength)
//		var padding = make([]byte, paddingLength)
//		rand.Reader.Read(padding)
//		s.mac.Reset()
//		var seqNumBytes = make([]byte, 4)
//		binary.BigEndian.PutUint32(seqNumBytes, s.seqNum)
//		s.mac.Write(seqNumBytes)
//		s.mac.Write(header)
//		s.mac.Write(payload)
//		s.mac.Write(padding)
//		var mac = s.mac.Sum(nil)
//		s.cipher.XORKeyStream(header, header)
//		s.cipher.XORKeyStream(payload, payload)
//		s.cipher.XORKeyStream(padding, padding)
//		w.Write(header)
//		w.Write(payload)
//		w.Write(padding)
//		w.Write(mac)
//		s.seqNum++
//		return nil
//	}
func generateKeyMaterial(out, tag []byte, r *kexResult) {
	var digestsSoFar []byte
	h := r.Hash.New()
	for len(out) > 0 {
		h.Reset()
		h.Write(r.K)
		h.Write(r.H)
		if len(digestsSoFar) == 0 {
			h.Write(tag)
			h.Write(r.SessionID)
		} else {
			h.Write(digestsSoFar)
		}
		digest := h.Sum(nil)
		n := copy(out, digest)
		out = out[n:]
		if len(out) > 0 {
			digestsSoFar = append(digestsSoFar, digest...)
		}
	}
}
