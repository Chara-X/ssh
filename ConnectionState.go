package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

type connectionState struct {
	*StreamPacketCipher
	seqNum           uint32
	dir              direction
	pendingKeyChange chan *StreamPacketCipher
}
type direction struct {
	ivTag     []byte
	keyTag    []byte
	macKeyTag []byte
}

func (s *connectionState) readPacket(r *bufio.Reader, strictMode bool) ([]byte, error) {
	packet, err := s.StreamPacketCipher.readCipherPacket(s.seqNum, r)
	s.seqNum++
	if err == nil && len(packet) == 0 {
		err = errors.New("ssh: zero length packet")
	}

	if len(packet) > 0 {
		switch packet[0] {
		case MsgNewKeys:
			select {
			case cipher := <-s.pendingKeyChange:
				s.StreamPacketCipher = cipher
				if strictMode {
					s.seqNum = 0
				}
			default:
				return nil, errors.New("ssh: got bogus newkeys message")
			}

		case msgDisconnect:
			// Transform a disconnect message into an
			// error. Since this is lowest level at which
			// we interpret message types, doing it here
			// ensures that we don't have to handle it
			// elsewhere.
			var msg disconnectMsg
			if err := ssh.Unmarshal(packet, &msg); err != nil {
				return nil, err
			}
			return nil, &msg
		}
	}

	// The packet may point to an internal buffer, so copy the
	// packet out here.
	fresh := make([]byte, len(packet))
	copy(fresh, packet)

	return fresh, err
}
func (s *connectionState) writePacket(w *bufio.Writer, rand io.Reader, packet []byte, strictMode bool) error {
	changeKeys := len(packet) > 0 && packet[0] == MsgNewKeys

	err := s.StreamPacketCipher.writeCipherPacket(s.seqNum, w, rand, packet)
	if err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}
	s.seqNum++
	if changeKeys {
		select {
		case cipher := <-s.pendingKeyChange:
			s.StreamPacketCipher = cipher
			if strictMode {
				s.seqNum = 0
			}
		default:
			panic("ssh: no key material for msgNewKeys")
		}
	}
	return err
}

type disconnectMsg struct {
	Reason   uint32 `sshtype:"1"`
	Message  string
	Language string
}

func (d *disconnectMsg) Error() string {
	return fmt.Sprintf("ssh: disconnect, reason %d: %s", d.Reason, d.Message)
}
