package ssh

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
)

const (
	prefixLen          = 5
	packetSizeMultiple = 16
	maxPacket          = 256 * 1024
)

type StreamPacketCipher struct {
	cipher      cipher.Stream
	prefix      [prefixLen]byte
	seqNumBytes [4]byte
	packetData  []byte
	mac         hash.Hash
	macResult   []byte
}

func (s *StreamPacketCipher) ReadCipherPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	if _, err := io.ReadFull(r, s.prefix[:]); err != nil {
		return nil, err
	}
	s.cipher.XORKeyStream(s.prefix[:], s.prefix[:])
	length := binary.BigEndian.Uint32(s.prefix[0:4])
	paddingLength := uint32(s.prefix[4])
	var macSize uint32
	if s.mac != nil {
		s.mac.Reset()
		binary.BigEndian.PutUint32(s.seqNumBytes[:], seqNum)
		s.mac.Write(s.seqNumBytes[:])
		s.mac.Write(s.prefix[:])
		macSize = uint32(s.mac.Size())
	}
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
	s.cipher.XORKeyStream(data, data)
	if s.mac != nil {
		s.mac.Write(data)
		s.macResult = s.mac.Sum(s.macResult[:0])
		if subtle.ConstantTimeCompare(s.macResult, mac) != 1 {
			return nil, errors.New("ssh: MAC failure")
		}
	}
	return s.packetData[:length-paddingLength-1], nil
}
func (s *StreamPacketCipher) WriteCipherPacket(seqNum uint32, w io.Writer, rand io.Reader, packet []byte) error {
	aadlen := 0
	paddingLength := packetSizeMultiple - (prefixLen+len(packet)-aadlen)%packetSizeMultiple
	if paddingLength < 4 {
		paddingLength += packetSizeMultiple
	}
	length := len(packet) + 1 + paddingLength
	binary.BigEndian.PutUint32(s.prefix[:], uint32(length))
	s.prefix[4] = byte(paddingLength)
	var padding = make([]byte, paddingLength)
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}
	if s.mac != nil {
		s.mac.Reset()
		binary.BigEndian.PutUint32(s.seqNumBytes[:], seqNum)
		s.mac.Write(s.seqNumBytes[:])
		s.mac.Write(s.prefix[:])
		s.mac.Write(packet)
		s.mac.Write(padding)
	}
	s.cipher.XORKeyStream(s.prefix[:], s.prefix[:])
	s.cipher.XORKeyStream(packet, packet)
	s.cipher.XORKeyStream(padding, padding)
	w.Write(s.prefix[:])
	w.Write(packet)
	w.Write(padding)
	if s.mac != nil {
		s.macResult = s.mac.Sum(s.macResult[:0])
		if _, err := w.Write(s.macResult); err != nil {
			return err
		}
	}
	return nil
}
