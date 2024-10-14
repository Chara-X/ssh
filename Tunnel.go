package tunnel

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log"
	random "math/rand"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"

	"github.com/Chara-X/tunnel/msg"
	"golang.org/x/crypto/ssh"
)

type Tunnel struct {
	conns          sync.Map
	stateR, stateW ConnState
	net.Conn
	ClientVersion, ServerVersion []byte
}

func New(conn net.Conn, config *Config) *Tunnel {
	var t = &Tunnel{stateR: ConnState{Cipher: noneCipher{}}, stateW: ConnState{Cipher: noneCipher{}}, Conn: conn, ClientVersion: []byte("SSH-2.0-Go")}
	t.Write(append(t.ClientVersion, "\r\n"...))
	var scanner = bufio.NewScanner(t)
	scanner.Scan()
	t.ServerVersion = scanner.Bytes()
	// Algorithm negotiation
	var algosReq = &msg.KexInit{KexAlgos: KeyExchanges, ServerHostKeyAlgos: HostKeyAlgorithms, CiphersClientServer: Ciphers, CiphersServerClient: Ciphers, MACsClientServer: MACs, MACsServerClient: MACs, CompressionClientServer: Compression, CompressionServerClient: Compression}
	rand.Read(algosReq.Cookie[:])
	var algosRep = t.exchange(algosReq)
	// Key exchange
	var k, h, hostKey, sig = KeyExchange(t, t.ClientVersion, t.ServerVersion, ssh.Marshal(algosReq), ssh.Marshal(algosRep))
	// Server authentication
	if err := hostKey.Verify(h, sig); err != nil {
		panic(err)
	}
	// Connected
	t.exchange(&msg.Msg{SSHType: 21})
	// Key derivation
	t.stateR.Cipher, t.stateR.Mac = KeyDerive(k, h, "BDF")
	t.stateW.Cipher, t.stateW.Mac = KeyDerive(k, h, "ACE")
	// Client authentication
	if _, ok := t.exchange(&msg.ServiceRequest{Service: "ssh-userauth"}).(*msg.ServiceAccept); !ok {
		panic(fmt.Sprintln("Service request failed"))
	}
	var authRep = t.exchange(&msg.PasswordAuth{User: config.User, Service: "ssh-connection", Method: "password", Password: config.Password})
	switch authRep := authRep.(type) {
	case *msg.UserAuthBanner:
		log.Println(authRep.Message)
		if t.Recv().(*msg.Msg).SSHType != 52 {
			panic("User authentication failed")
		}
	case *msg.Msg:
		if authRep.SSHType != 52 {
			panic("User authentication failed")
		}
	}
	go func() {
		for {
			switch payload := t.Recv().(type) {
			case *msg.ChannelOpenConfirm:
				var v, _ = t.conns.Load(payload.RemoteID)
				var c = v.(*Conn)
				c.ch <- payload
			case *msg.ChannelData:
				var v, _ = t.conns.Load(payload.RemoteID)
				var c = v.(*Conn)
				c.pipeW.Write([]byte(payload.Data))
			default:
				log.Println("UnHandled SSH type:", reflect.TypeOf(payload))
			}
		}
	}()
	return t
}
func (t *Tunnel) Shell() *Conn {
	var c = t.Open("session", nil)
	c.Send("shell", nil)
	return c
}
func (t *Tunnel) Dial(addr string) *Conn {
	var ip, portString, _ = net.SplitHostPort(addr)
	var port, _ = strconv.Atoi(portString)
	var c = t.Open("direct-tcpip", ssh.Marshal(struct {
		RAddr string
		RPort uint32
		LAddr string
		LPort uint32
	}{
		RAddr: ip,
		RPort: uint32(port),
		LAddr: "0.0.0.0",
		LPort: 0,
	}))
	return c
}
func (t *Tunnel) Open(name string, data []byte) *Conn {
	var c = &Conn{tunnel: t, ch: make(chan interface{}), LocalID: random.Uint32()}
	c.pipeR, c.pipeW, _ = os.Pipe()
	t.conns.Store(c.LocalID, c)
	t.Send(&msg.ChannelOpen{ChanType: name, LocalID: c.LocalID, LocalWindow: 1024, MaxPacketSize: 1024, TypeSpecificData: data})
	c.RemoteID = c.Recv().(*msg.ChannelOpenConfirm).LocalID
	return c
}
func (t *Tunnel) Recv() interface{} {
	var header = make([]byte, 5)
	t.Read(header)
	t.stateR.Cipher.XORKeyStream(header, header)
	var length, paddingLength = binary.BigEndian.Uint32(header[0:4]), uint32(header[4])
	var body = make([]byte, length-1)
	t.Read(body)
	t.stateR.Cipher.XORKeyStream(body, body)
	if t.stateR.Mac != nil {
		var mac = make([]byte, t.stateR.Mac.Size())
		t.Read(mac)
		t.stateR.Mac.Reset()
		binary.Write(t.stateR.Mac, binary.BigEndian, t.stateR.SeqNum)
		t.stateR.Mac.Write(header)
		t.stateR.Mac.Write(body)
		if subtle.ConstantTimeCompare(t.stateR.Mac.Sum(nil), mac) != 1 {
			panic("ssh: MAC failure")
		}
	}
	t.stateR.SeqNum++
	var payload = body[:length-paddingLength-1]
	var rep = reflect.New(msg.TypeMapper[payload[0]]).Interface()
	if err := ssh.Unmarshal(payload, rep); err != nil {
		panic(err)
	}
	return rep
}
func (t *Tunnel) Send(req interface{}) {
	var payload = ssh.Marshal(req)
	var paddingLength = aes.BlockSize - (5+len(payload))%aes.BlockSize
	if paddingLength < 4 {
		paddingLength += aes.BlockSize
	}
	var length = len(payload) + 1 + paddingLength
	var header = make([]byte, 5)
	binary.BigEndian.PutUint32(header, uint32(length))
	header[4] = byte(paddingLength)
	var padding = make([]byte, paddingLength)
	rand.Reader.Read(padding)
	if t.stateW.Mac != nil {
		t.stateW.Mac.Reset()
		binary.Write(t.stateW.Mac, binary.BigEndian, t.stateW.SeqNum)
		t.stateW.Mac.Write(header)
		t.stateW.Mac.Write(payload)
		t.stateW.Mac.Write(padding)
	}
	t.stateW.Cipher.XORKeyStream(header, header)
	t.stateW.Cipher.XORKeyStream(payload, payload)
	t.stateW.Cipher.XORKeyStream(padding, padding)
	t.Write(header)
	t.Write(payload)
	t.Write(padding)
	if t.stateW.Mac != nil {
		t.Write(t.stateW.Mac.Sum(nil))
	}
	t.stateW.SeqNum++
}
func (t *Tunnel) exchange(req interface{}) interface{} {
	t.Send(req)
	return t.Recv()
}

//	func (t *Tunnel) Shell() *Conn {
//		var ch = t.Open("session", nil)
//		// c.writeCipherPacket(msg.ChannelRequest{PeersID: ch.id, Request: "shell"})
//		return ch
//	}
//
//	func (t *Tunnel) Dial(addr string) *Conn {
//		var payload = bytes.NewBuffer(nil)
//		var host, portString, _ = net.SplitHostPort(addr)
//		var rAddr = net.ParseIP(host).To4().String()
//		var rPort, _ = strconv.Atoi(portString)
//		binary.Write(payload, binary.BigEndian, uint32(len(rAddr)))
//		payload.WriteString(rAddr)
//		binary.Write(payload, binary.BigEndian, uint32(rPort))
//		binary.Write(payload, binary.BigEndian, uint32(7))
//		payload.WriteString("0.0.0.0")
//		binary.Write(payload, binary.BigEndian, uint32(0))
//		return t.Open("direct-tcpip", payload.Bytes())
//	}
