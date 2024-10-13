package tunnel

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"sync"

	"github.com/Chara-X/tunnel/msg"
	"golang.org/x/crypto/ssh"
)

type Tunnel struct {
	conns          sync.Map
	rState, wState ConnState
	net.Conn
	ClientVersion, ServerVersion []byte
}

func New(conn net.Conn, config *ssh.ClientConfig) *Tunnel {
	var t = &Tunnel{rState: ConnState{Cipher: noneCipher{}}, wState: ConnState{Cipher: noneCipher{}}, Conn: conn, ClientVersion: []byte("SSH-2.0-Go")}
	t.Write(append(t.ClientVersion, "\r\n"...))
	var scanner = bufio.NewScanner(t)
	scanner.Scan()
	t.ServerVersion = scanner.Bytes()
	// Algorithm negotiation
	var algosReq = &msg.KexInit{KexAlgos: config.KeyExchanges, ServerHostKeyAlgos: config.HostKeyAlgorithms, CiphersClientServer: config.Ciphers, CiphersServerClient: config.Ciphers, MACsClientServer: config.MACs, MACsServerClient: config.MACs, CompressionClientServer: []string{"none"}, CompressionServerClient: []string{"none"}}
	rand.Read(algosReq.Cookie[:])
	var algosRep = t.Exchange(algosReq)
	// Key exchange
	var k, h, hostKey, sig = KeyExchange(t, t.ClientVersion, t.ServerVersion, ssh.Marshal(algosReq), ssh.Marshal(algosRep))
	// Server authentication
	if err := hostKey.Verify(h, sig); err != nil {
		panic(err)
	}
	// Connected
	t.Exchange(&msg.Msg{SSHType: 21})
	// Key derivation
	t.rState.Cipher, t.rState.Mac = KeyDerive(k, h, "BDF")
	t.wState.Cipher, t.wState.Mac = KeyDerive(k, h, "ACE")
	// Client authentication
	if _, ok := t.Exchange(&msg.ServiceRequest{Service: "ssh-userauth"}).(*msg.ServiceAccept); !ok {
		panic(fmt.Sprintln("Service request failed"))
	}
	if _, ok := t.Exchange(&msg.PasswordAuth{User: config.User, Service: "ssh-connection", Method: "password", Password: "123"}).(*msg.Msg); !ok {
		panic(fmt.Sprintln("User auth failed"))
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
func (t *Tunnel) Open(req *msg.ChannelOpen) *Conn {
	var c = &Conn{tunnel: t, ch: make(chan interface{})}
	c.pipeR, c.pipeW, _ = os.Pipe()
	t.conns.Store(c.LocalID, c)
	t.Send(req)
	c.RemoteID = (<-c.ch).(*msg.ChannelOpenConfirm).LocalID
	if req.ChanType == "session" {
		t.Send(&msg.ChannelRequest{PeersID: c.RemoteID, Request: "shell"})
	}
	return c
}
func (t *Tunnel) Exchange(req interface{}) interface{} {
	t.Send(req)
	return t.Recv()
}
func (s *Tunnel) Recv() interface{} {
	var header = make([]byte, 5)
	s.Read(header)
	s.rState.Cipher.XORKeyStream(header, header)
	var length, paddingLength = binary.BigEndian.Uint32(header[0:4]), uint32(header[4])
	var body = make([]byte, length-1)
	s.Read(body)
	s.rState.Cipher.XORKeyStream(body, body)
	if s.rState.Mac != nil {
		var mac = make([]byte, s.rState.Mac.Size())
		s.Read(mac)
		s.rState.Mac.Reset()
		binary.Write(s.rState.Mac, binary.BigEndian, s.rState.SeqNum)
		s.rState.Mac.Write(header)
		s.rState.Mac.Write(body)
		if subtle.ConstantTimeCompare(s.rState.Mac.Sum(nil), mac) != 1 {
			panic("ssh: MAC failure")
		}
	}
	s.rState.SeqNum++
	var payload = body[:length-paddingLength-1]
	var rep = reflect.New(msg.TypeMapper[payload[0]]).Interface()
	if err := ssh.Unmarshal(payload, rep); err != nil {
		panic(err)
	}
	return rep
}
func (s *Tunnel) Send(req interface{}) {
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
	if s.wState.Mac != nil {
		s.wState.Mac.Reset()
		binary.Write(s.wState.Mac, binary.BigEndian, s.wState.SeqNum)
		s.wState.Mac.Write(header)
		s.wState.Mac.Write(payload)
		s.wState.Mac.Write(padding)
	}
	s.wState.Cipher.XORKeyStream(header, header)
	s.wState.Cipher.XORKeyStream(payload, payload)
	s.wState.Cipher.XORKeyStream(padding, padding)
	s.Write(header)
	s.Write(payload)
	s.Write(padding)
	if s.wState.Mac != nil {
		s.Write(s.wState.Mac.Sum(nil))
	}
	s.wState.SeqNum++
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
