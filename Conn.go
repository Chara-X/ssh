package ssh

import (
	"bufio"
	"crypto/aes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	random "math/rand"
	"net"
	"sync"

	"github.com/Chara-X/ssh/msg"
	"golang.org/x/crypto/ssh"
)

type Conn struct {
	chans       *sync.Map
	bufReader   *bufio.Reader
	bufWriter   *bufio.Writer
	readCipher  *connectionState
	writeCipher *connectionState
	net.Conn
	User          string
	SessionID     []byte
	ClientVersion string
	ServerVersion string
}

func NewConn(conn net.Conn, config *ssh.ClientConfig) *Conn {
	var c = &Conn{Conn: conn, User: config.User, ClientVersion: "SSH-2.0-Go"}
	c.Write([]byte(c.ClientVersion + "\r\n"))
	var scanner = bufio.NewScanner(c)
	scanner.Scan()
	c.ServerVersion = scanner.Text()
	// Key algos
	var algosReq = &msg.KexAlgos{KexAlgos: config.KeyExchanges, ServerHostKeyAlgos: config.HostKeyAlgorithms, CiphersClientServer: config.Ciphers, CiphersServerClient: config.Ciphers, MACsClientServer: config.MACs, MACsServerClient: config.MACs, CompressionClientServer: []string{"none"}, CompressionServerClient: []string{"none"}}
	rand.Read(algosReq.Cookie[:])
	c.WritePacket(algosReq)
	var algosRep = &msg.KexAlgos{}
	c.ReadPacket(algosRep)
	// Key exchange
	var ecdhAlg = &ECDH{curve: elliptic.P256()}
	var kexRes, _ = ecdhAlg.Client(c, rand.Reader, &handshakeMagics{clientVersion: []byte(c.ClientVersion), serverVersion: []byte(c.ServerVersion), clientKexInit: ssh.Marshal(algosReq), serverKexInit: ssh.Marshal(algosRep)})
	c.SessionID = kexRes.H
	kexRes.SessionID = c.SessionID
	// Verify host key
	var hostKey, _ = ssh.ParsePublicKey(kexRes.HostKey)
	var sig = &ssh.Signature{}
	ssh.Unmarshal(kexRes.Signature, sig)
	fmt.Println("Host key verify:", hostKey.Verify(kexRes.H, sig))
	// New keys
	c.WritePacket(&msg.Msg{SSHType: 21})
	var newKeysRep = &msg.Msg{}
	c.ReadPacket(newKeysRep)
	fmt.Println(newKeysRep.SSHType)
	// Key derivation
	c.bufReader = bufio.NewReader(c)
	c.bufWriter = bufio.NewWriter(c)
	// c.readCipher = &connectionState{pendingKeyChange: make(chan *StreamPacketCipher, 1)}
	c.readCipher = &connectionState{pendingKeyChange: make(chan *StreamPacketCipher, 1), seqNum: 3, StreamPacketCipher: NewStreamPacketCipher(direction{[]byte{'B'}, []byte{'D'}, []byte{'F'}}, kexRes)}
	c.writeCipher = &connectionState{pendingKeyChange: make(chan *StreamPacketCipher, 1), seqNum: 3, StreamPacketCipher: NewStreamPacketCipher(direction{[]byte{'A'}, []byte{'C'}, []byte{'E'}}, kexRes)}
	// c.writeCipher = &connectionState{pendingKeyChange: make(chan *StreamPacketCipher, 1)}
	// c.readCipher.pendingKeyChange <- NewStreamPacketCipher(direction{[]byte{'B'}, []byte{'D'}, []byte{'F'}}, kexRes)
	// c.writeCipher.pendingKeyChange <- NewStreamPacketCipher(direction{[]byte{'A'}, []byte{'C'}, []byte{'E'}}, kexRes)
	// Client authentication
	if err := c.WriteCipherPacket(&msg.ServiceRequest{Service: "ssh-userauth"}); err != nil {
		panic(err)
	}
	var serviceAccept = &msg.ServiceAccept{}
	if err := c.ReadCipherPacket(serviceAccept); err != nil {
		panic(err)
	}
	c.WriteCipherPacket(&msg.PasswordAuth{
		User:     config.User,
		Service:  "ssh-connection",
		Method:   "password",
		Password: "123",
	})
	var userAuthBanner = &msg.UserAuthBanner{}
	if err := c.ReadCipherPacket(userAuthBanner); err != nil {
		panic(err)
	}
	fmt.Println(userAuthBanner.Message)
	var authRes = &msg.Msg{}
	if err := c.ReadCipherPacket(authRes); err != nil || authRes.SSHType != 52 {
		panic(fmt.Sprintln("User auth failed"))
	} else {
		fmt.Println("User auth success")
	}
	return c
}
func (c *Conn) ReadCipherPacket(msg interface{}) error {
	var packet, err = c.readCipher.readPacket(c.bufReader, false)
	if err != nil {
		return err
	}
	ssh.Unmarshal(packet, msg)
	return nil
}
func (c *Conn) WriteCipherPacket(msg interface{}) error {
	var packet = ssh.Marshal(msg)
	return c.writeCipher.writePacket(c.bufWriter, rand.Reader, packet, false)
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
func (c *Conn) OpenChannel(name string, payload []byte) *Channel {
	var ch = &Channel{chanType: name, conn: c}
	ch.id = random.Uint32()
	c.chans.Store(ch.id, ch)
	c.WriteCipherPacket(&msg.ChannelOpen{
		ChanType:         name,
		PeersWindow:      1024 * 10,
		MaxPacketSize:    1024 * 10,
		TypeSpecificData: payload,
		PeersID:          ch.id,
	})
	var confirm = &msg.ChannelOpenConfirm{}
	if err := c.ReadCipherPacket(confirm); err != nil {
		panic(err)
	}
	return ch
}

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
// Key exchange
// var ecdhKey, _ = ecdh.P256().GenerateKey(rand.Reader)
// var ecdhReq = &msg.KexRequest{PubKey: ecdhKey.PublicKey().Bytes()}
// c.WritePacket(ecdhReq)
// var ecdhRep = &msg.KexReply{}
// c.ReadPacket(ecdhRep)
// var pubKey, _ = ecdh.P256().NewPublicKey(ecdhRep.PubKey)
// var secret, _ = ecdhKey.ECDH(pubKey)
// var sha = sha256.New()
// writeString(sha, []byte(c.ClientVersion))
// writeString(sha, []byte(c.ServerVersion))
// writeString(sha, ssh.Marshal(algosReq))
// writeString(sha, ssh.Marshal(algosRep))
// writeString(sha, ecdhRep.HostKey)
// writeString(sha, ecdhReq.PubKey)
// writeString(sha, ecdhRep.PubKey)
// sha.Write(secret)
// c.SessionID = sha.Sum(nil)
