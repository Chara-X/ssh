package ssh

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"

	"github.com/Chara-X/ssh/msg"
	"golang.org/x/crypto/ssh"
)

type Conn struct {
	// chans *sync.Map
	net.Conn
	User          string
	ClientVersion string
	ServerVersion string
}

func NewClientConn(conn net.Conn, config *ssh.ClientConfig) Conn {
	var c = Conn{Conn: conn, User: config.User, ClientVersion: "SSH-2.0-Go"}
	c.Write([]byte(c.ClientVersion + "\r\n"))
	var scanner = bufio.NewScanner(c)
	scanner.Scan()
	c.ServerVersion = scanner.Text()
	var payload = &msg.KexInit{
		KexAlgos:                append(config.KeyExchanges, "ext-info-c", "kex-strict-c-v00@openssh.com"),
		ServerHostKeyAlgos:      config.HostKeyAlgorithms,
		CiphersClientServer:     config.Ciphers,
		CiphersServerClient:     config.Ciphers,
		MACsClientServer:        config.MACs,
		MACsServerClient:        config.MACs,
		CompressionClientServer: []string{"none"},
		CompressionServerClient: []string{"none"},
	}
	rand.Read(payload.Cookie[:])
	c.WritePacket(ssh.Marshal(payload))
	// go func() {
	// 	for {
	// 		var packet = c.readPacket()
	// 		if v, ok := c.chans.Load(binary.BigEndian.Uint32(packet[1:])); ok {
	// 			var ch = v.(*Channel)
	// 			switch packet[0] {
	// 			case MsgChannelData:
	// 				ch.bufW.Write(packet[9:])
	// 			}
	// 		}
	// 	}
	// }()
	return c
}
func (c *Conn) ReadPacket() []byte {
	var length = make([]byte, 4)
	io.ReadFull(c, length)
	var payload = make([]byte, binary.BigEndian.Uint32(length))
	io.ReadFull(c, payload)
	return payload
}
func (c *Conn) WritePacket(payload []byte) {
	var length = make([]byte, 4)
	var paddingLength = packetSizeMultiple - (prefixLen+len(payload))%packetSizeMultiple
	if paddingLength < 4 {
		paddingLength += packetSizeMultiple
	}
	binary.BigEndian.PutUint32(length, uint32(len(payload)))
	c.Write(length)
	c.Write(payload)
}

// func (c *Conn) readCipherPacket() []byte {
// 	panic("not implemented")
// }
// func (c *Conn) writeCipherPacket(packet []byte) {
// 	panic("not implemented")
// }

//	func (c *Conn) OpenChannel(name string, payload []byte) *Channel {
//		var ch = &Channel{chanType: name, conn: c}
//		ch.id = rand.Uint32()
//		c.chans.Store(ch.id, ch)
//		var packet = bytes.NewBuffer([]byte{MsgChannelOpen})
//		binary.Write(packet, binary.BigEndian, uint32(len(name)))
//		packet.WriteString(name)
//		binary.Write(packet, binary.BigEndian, ch.id)
//		binary.Write(packet, binary.BigEndian, uint32(1024*100))
//		binary.Write(packet, binary.BigEndian, uint32(1024*100))
//		binary.Write(packet, binary.BigEndian, uint32(len(payload)))
//		packet.Write(payload)
//		c.writePacket(packet.Bytes())
//		return ch
//	}
