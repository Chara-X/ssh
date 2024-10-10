package ssh

import (
	"bufio"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Chara-X/ssh/msg"
	"golang.org/x/crypto/ssh"
)

type Conn struct {
	// chans *sync.Map
	readCipher  *StreamPacketCipher
	writeCipher *StreamPacketCipher
	net.Conn
	User          string
	SessionID     []byte
	ClientVersion string
	ServerVersion string
}

func NewClientConn(conn net.Conn, config *ssh.ClientConfig) Conn {
	var c = Conn{Conn: conn, User: config.User, ClientVersion: "SSH-2.0-Go"}
	c.Write([]byte(c.ClientVersion + "\r\n"))
	var scanner = bufio.NewScanner(c)
	scanner.Scan()
	c.ServerVersion = scanner.Text()
	// Key algos
	var algosRep = &msg.KexAlgos{}
	c.ReadPacket(algosRep)
	var algosReq = &msg.KexAlgos{KexAlgos: config.KeyExchanges, ServerHostKeyAlgos: config.HostKeyAlgorithms, CiphersClientServer: config.Ciphers, CiphersServerClient: config.Ciphers, MACsClientServer: config.MACs, MACsServerClient: config.MACs, CompressionClientServer: []string{"none"}, CompressionServerClient: []string{"none"}}
	rand.Read(algosReq.Cookie[:])
	c.WritePacket(algosReq)
	// Key exchange
	var ecdhKey, _ = ecdh.P256().GenerateKey(rand.Reader)
	var ecdhReq = &msg.KexRequest{PubKey: ecdhKey.PublicKey().Bytes()}
	c.WritePacket(ecdhReq)
	var ecdhRep = &msg.KexReply{}
	c.ReadPacket(ecdhRep)
	var pubKey, _ = ecdh.P256().NewPublicKey(ecdhRep.PubKey)
	var secret, _ = ecdhKey.ECDH(pubKey)
	var sha = sha256.New()
	sha.Write([]byte(c.ClientVersion))
	sha.Write([]byte(c.ServerVersion))
	sha.Write(ssh.Marshal(algosReq))
	sha.Write(ssh.Marshal(algosRep))
	sha.Write(ecdhRep.HostKey)
	sha.Write(ecdhReq.PubKey)
	sha.Write(ecdhRep.PubKey)
	sha.Write(secret)
	c.SessionID = sha.Sum(nil)
	// Key derivation
	c.readCipher = NewStreamPacketCipher(secret, c.SessionID, "BDF")
	c.writeCipher = NewStreamPacketCipher(secret, c.SessionID, "ACE")
	// New keys
	var newKeysRep = &msg.Msg{}
	c.ReadPacket(newKeysRep)
	c.WritePacket(&msg.Msg{SSHType: 21})
	for {
		fmt.Println("Session:")
		// var channelOpenReq = &msg.ChannelOpen{
		// 	ChanType:      "session",
		// 	PeersID:       0,
		// 	PeersWindow:   1024 * 100,
		// 	MaxPacketSize: 1024 * 100,
		// }
		// c.WriteCipherPacket(channelOpenReq)
		var channelOpenRep = &msg.Msg{}
		c.ReadCipherPacket(channelOpenRep)
		fmt.Println(channelOpenRep.SSHType)
		time.Sleep(time.Second)
	}
	return c
}
func (c *Conn) ReadCipherPacket(msg interface{}) error {
	return c.readCipher.ReadCipherPacket(c, msg)
}
func (c *Conn) WriteCipherPacket(msg interface{}) error {
	return c.writeCipher.WriteCipherPacket(c, msg)
}
func (c *Conn) ReadPacket(msg interface{}) {
	var length = make([]byte, 4)
	c.Read(length)
	var paddingLength = make([]byte, 1)
	c.Read(paddingLength)
	var bodyLength = binary.BigEndian.Uint32(length) - 1
	var body = make([]byte, bodyLength)
	c.Read(body)
	ssh.Unmarshal(body[:int(bodyLength)-int(paddingLength[0])], msg)
}
func (c *Conn) WritePacket(msg interface{}) {
	var payload = ssh.Marshal(msg)
	var paddingLength = aes.BlockSize - (5+len(payload))%aes.BlockSize
	if paddingLength < 4 {
		paddingLength += aes.BlockSize
	}
	var length = 1 + len(payload) + int(paddingLength)
	binary.Write(c, binary.BigEndian, uint32(length))
	c.Write([]byte{byte(paddingLength)})
	c.Write(payload)
	var padding = make([]byte, paddingLength)
	rand.Read(padding)
	c.Write(padding)
}

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
// go func() {
// 	for {
// 		var packet = c.ReadPacket()
// 		if v, ok := c.chans.Load(binary.BigEndian.Uint32(packet[1:])); ok {
// 			var ch = v.(*Channel)
// 			switch packet[0] {
// 			case MsgChannelData:
// 				ch.bufW.Write(packet[9:])
// 			}
// 		}
// 	}
// }()
