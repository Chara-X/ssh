package tunnel

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"log"
	"net"
	"reflect"
	"sync"

	"github.com/Chara-X/tunnel/msg"
	"golang.org/x/crypto/ssh"
)

type Conn struct {
	chs            sync.Map
	stateR, stateW ConnState
	net.Conn
	ClientVersion, ServerVersion []byte
}

func Connect(network, address string, config *Config) *Conn {
	var conn, _ = net.Dial(network, address)
	var c = &Conn{stateR: ConnState{Cipher: noneCipher{}}, stateW: ConnState{Cipher: noneCipher{}}, Conn: conn, ClientVersion: []byte("SSH-2.0-Go")}
	c.Write(append(c.ClientVersion, "\r\n"...))
	var scanner = bufio.NewScanner(c)
	scanner.Scan()
	c.ServerVersion = scanner.Bytes()
	var algosReq = &msg.KexInit{KexAlgos: KeyExchanges, ServerHostKeyAlgos: HostKeyAlgorithms, CiphersClientServer: Ciphers, CiphersServerClient: Ciphers, MACsClientServer: MACs, MACsServerClient: MACs, CompressionClientServer: Compression, CompressionServerClient: Compression}
	rand.Read(algosReq.Cookie[:])
	var algosRep = c.exchange(algosReq)
	var k, h, hostKey, sig = KeyExchange(c, c.ClientVersion, c.ServerVersion, ssh.Marshal(algosReq), ssh.Marshal(algosRep))
	if err := hostKey.Verify(h, sig); err != nil {
		panic("Server auth failed")
	}
	c.exchange(&msg.Msg{SSHType: 21})
	c.stateR.Cipher, c.stateR.Mac = KeyDerive(k, h, "BDF")
	c.stateW.Cipher, c.stateW.Mac = KeyDerive(k, h, "ACE")
	c.exchange(&msg.ServiceRequest{Service: "ssh-userauth"})
	c.Send(&msg.UserAuthRequest{User: config.User, Service: "ssh-connection", Method: "password", Password: config.Password})
	for {
		var authRep = c.Recv()
		if _, ok := authRep.(*msg.Msg); ok && authRep.(*msg.Msg).SSHType == 52 {
			break
		} else if v, ok := authRep.(*msg.UserAuthBanner); ok {
			log.Println(v.Message)
		} else {
			panic("Client auth failed")
		}
	}
	go func() {
		for {
			switch rep := c.Recv().(type) {
			case *msg.ChannelOpenConfirm:
				var v, _ = c.chs.Load(rep.RemoteID)
				var ch = v.(*Channel)
				ch.ch <- rep
			case *msg.ChannelData:
				var v, _ = c.chs.Load(rep.RemoteID)
				var ch = v.(*Channel)
				ch.pipeW.Write([]byte(rep.Data))
			default:
				log.Println("Unhandled SSH type:", reflect.TypeOf(rep))
			}
		}
	}()
	return c
}
func (c *Conn) Recv() interface{} {
	var header = make([]byte, 5)
	c.Read(header)
	c.stateR.Cipher.XORKeyStream(header, header)
	var length, paddingLength = binary.BigEndian.Uint32(header[0:4]), uint32(header[4])
	var body = make([]byte, length-1)
	c.Read(body)
	c.stateR.Cipher.XORKeyStream(body, body)
	if c.stateR.Mac != nil {
		var mac = make([]byte, c.stateR.Mac.Size())
		c.Read(mac)
		c.stateR.Mac.Reset()
		binary.Write(c.stateR.Mac, binary.BigEndian, c.stateR.SeqNum)
		c.stateR.Mac.Write(header)
		c.stateR.Mac.Write(body)
		if subtle.ConstantTimeCompare(c.stateR.Mac.Sum(nil), mac) != 1 {
			panic("MAC failure")
		}
	}
	c.stateR.SeqNum++
	var payload = body[:length-paddingLength-1]
	if v, ok := msg.TypeMapper[payload[0]]; ok {
		var rep = reflect.New(v).Interface()
		ssh.Unmarshal(payload, rep)
		return rep
	}
	log.Panicln("Unknown SSH type:", payload[0])
	return nil
}
func (c *Conn) Send(req interface{}) {
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
	if c.stateW.Mac != nil {
		c.stateW.Mac.Reset()
		binary.Write(c.stateW.Mac, binary.BigEndian, c.stateW.SeqNum)
		c.stateW.Mac.Write(header)
		c.stateW.Mac.Write(payload)
		c.stateW.Mac.Write(padding)
	}
	c.stateW.Cipher.XORKeyStream(header, header)
	c.stateW.Cipher.XORKeyStream(payload, payload)
	c.stateW.Cipher.XORKeyStream(padding, padding)
	c.Write(header)
	c.Write(payload)
	c.Write(padding)
	if c.stateW.Mac != nil {
		c.Write(c.stateW.Mac.Sum(nil))
	}
	c.stateW.SeqNum++
}
func (t *Conn) exchange(req interface{}) interface{} {
	t.Send(req)
	return t.Recv()
}
