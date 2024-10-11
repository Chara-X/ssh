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

func NewStreamPacketCipher(dir direction, kex *kexResult) *StreamPacketCipher {
	var iv, key, macKey = make([]byte, aes.BlockSize), make([]byte, 32), make([]byte, 32)
	generateKeyMaterial(iv, dir.ivTag, kex)
	generateKeyMaterial(key, dir.keyTag, kex)
	generateKeyMaterial(macKey, dir.macKeyTag, kex)
	var block, err = aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
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
	paddingLength := packetSizeMultiple - (prefixLen+len(packet))%packetSizeMultiple
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
