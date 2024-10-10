package ssh

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"

	"github.com/Chara-X/ssh/msg"
	"golang.org/x/crypto/ssh"
)

type Conn struct {
	// chans *sync.Map
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
	// Algorithm negotiation
	var algosRes = &msg.KexAlgos{}
	ssh.Unmarshal(c.ReadPacket(), algosRes)
	var algosReq = &msg.KexAlgos{KexAlgos: []string{"ecdh-sha2-nistp256"}, ServerHostKeyAlgos: []string{"ecdsa-sha2-nistp256"}, CiphersClientServer: []string{"aes256-ctr"}, CiphersServerClient: []string{"aes256-ctr"}, MACsClientServer: []string{"hmac-sha2-256"}, MACsServerClient: []string{"hmac-sha2-256"}, CompressionClientServer: []string{"none"}, CompressionServerClient: []string{"none"}}
	rand.Read(algosReq.Cookie[:])
	c.WritePacket(ssh.Marshal(algosReq))
	// Key exchange
	var ecdhKey, _ = ecdh.P256().GenerateKey(rand.Reader)
	var ecdhReq = &msg.KexRequest{PubKey: ecdhKey.PublicKey().Bytes()}
	c.WritePacket(ssh.Marshal(ecdhReq))
	var ecdhRes = &msg.KexReply{}
	var p2 = c.ReadPacket()
	ssh.Unmarshal(p2, ecdhRes)
	var pubKey, _ = ecdh.P256().NewPublicKey(ecdhRes.PubKey)
	var secret, _ = ecdhKey.ECDH(pubKey)
	var sha = sha256.New()
	sha.Write(secret)
	c.SessionID = sha.Sum(nil)
	var iv = make([]byte, aes.BlockSize)
	var key = make([]byte, 32)
	var macKey = make([]byte, 32)
	generateKey(secret, c.SessionID, 'A', iv)
	generateKey(secret, c.SessionID, 'C', key)
	generateKey(secret, c.SessionID, 'E', macKey)
	var block, _ = aes.NewCipher(key)
	var stream = cipher.NewCTR(block, iv)
	var streamDump []byte
	for remainingToDump := 0; remainingToDump > 0; {
		dumpThisTime := remainingToDump
		if dumpThisTime > len(streamDump) {
			dumpThisTime = len(streamDump)
		}
		stream.XORKeyStream(streamDump[:dumpThisTime], streamDump[:dumpThisTime])
		remainingToDump -= dumpThisTime
	}
	var mac = hmac.New(sha256.New, macKey)
	_ = &StreamPacketCipher{
		mac:       mac,
		macResult: make([]byte, mac.Size()),
		cipher:    stream,
	}
	return c
}
func (c *Conn) ReadPacket() []byte {
	var length = make([]byte, 4)
	c.Read(length)
	var paddingLength = make([]byte, 1)
	c.Read(paddingLength)
	var bodyLength = binary.BigEndian.Uint32(length) - 1
	var body = make([]byte, bodyLength)
	c.Read(body)
	return body[:int(bodyLength)-int(paddingLength[0])]
}
func (c *Conn) WritePacket(payload []byte) {
	var paddingLength = blockSize - (5+len(payload))%blockSize
	if paddingLength < 4 {
		paddingLength += blockSize
	}
	var length = 1 + len(payload) + int(paddingLength)
	binary.Write(c, binary.BigEndian, uint32(length))
	c.Write([]byte{byte(paddingLength)})
	c.Write(payload)
	var padding = make([]byte, paddingLength)
	rand.Read(padding)
	c.Write(padding)
}
func generateKey(k, h []byte, c byte, out []byte) {
	var digestsSoFar []byte
	var sha = sha256.New()
	for len(out) > 0 {
		sha.Write(k)
		sha.Write(h)
		if len(digestsSoFar) == 0 {
			sha.Write([]byte{c})
			sha.Write(h)
		} else {
			sha.Write(digestsSoFar)
		}
		var digest = sha.Sum(nil)
		var n = copy(out, digest)
		out = out[n:]
		if len(out) > 0 {
			digestsSoFar = append(digestsSoFar, digest...)
		}
	}
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
