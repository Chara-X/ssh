package tunnel

import (
	"bufio"
	"crypto/rand"
	"log"
	"net"
	"os"
	"reflect"
	"sync"

	"github.com/Chara-X/tunnel/msg"
	"golang.org/x/crypto/ssh"
)

type Mux struct {
	cs sync.Map
	*Encoder
	*Decoder
}

func New(conn net.Conn, config *Config) *Mux {
	var t = &Mux{Encoder: NewEncoder(conn), Decoder: NewDecoder(conn)}
	conn.Write(append(ClientVersion, "\r\n"...))
	var scanner = bufio.NewScanner(conn)
	scanner.Scan()
	var algosReq = &msg.KexInit{KexAlgos: KeyExchanges, ServerHostKeyAlgos: HostKeyAlgorithms, CiphersClientServer: Ciphers, CiphersServerClient: Ciphers, MACsClientServer: MACs, MACsServerClient: MACs, CompressionClientServer: Compression, CompressionServerClient: Compression}
	rand.Read(algosReq.Cookie[:])
	t.Encode(algosReq)
	var k, h = KeyExchange(t, ClientVersion, scanner.Bytes(), ssh.Marshal(algosReq), ssh.Marshal(t.Decode()))
	t.Encode(&msg.Msg{SSHType: 21})
	t.Decode()
	t.Encoder.SetCipher(KeyDerive(k, h, "ACE"))
	t.Decoder.SetCipher(KeyDerive(k, h, "BDF"))
	t.Encode(&msg.ServiceRequest{Service: "ssh-userauth"})
	t.Decode()
	t.Encode(&msg.UserAuthRequest{User: config.User, Service: "ssh-connection", Method: "password", Password: config.Password})
	t.Decode()
	go func() {
		for {
			switch rep := t.Decode().(type) {
			case *msg.ChannelOpenConfirm:
				var v, _ = t.cs.Load(rep.Dst)
				var c = v.(*Conn)
				c.ch <- rep
			case *msg.ChannelData:
				var v, _ = t.cs.Load(rep.RemoteID)
				var c = v.(*Conn)
				c.pipeW.Write([]byte(rep.Data))
			default:
				log.Println("Unhandled SSH type:", reflect.TypeOf(rep))
			}
		}
	}()
	return t
}
func (t *Mux) Open(req *msg.ChannelOpen) *Conn {
	var c = &Conn{ch: make(chan interface{}, 1024), t: t, Src: req.Src}
	c.pipeR, c.pipeW, _ = os.Pipe()
	t.cs.Store(c.Src, c)
	t.Encode(req)
	c.Dst = (<-c.ch).(*msg.ChannelOpenConfirm).Src
	if req.ChanType == Session {
		t.Encode(&msg.ChannelRequest{RemoteID: c.Src, Request: Shell})
	}
	return c
}
