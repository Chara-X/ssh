package tunnel

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	ssh.Conn
	lns sync.Map
}

func NewClient(addr string, cfg *ssh.ClientConfig) *Client {
	var conn, _ = net.Dial("tcp", addr)
	var cli, ln = &Client{}, make(<-chan ssh.NewChannel)
	cli.Conn, ln, _, _ = ssh.NewClientConn(conn, addr, cfg)
	go func() {
		for ch := range ln {
			switch ch.ChannelType() {
			case "forwarded-tcpip":
				var payload = bytes.NewBuffer(ch.ExtraData())
				var ipLen uint32
				binary.Read(payload, binary.BigEndian, &ipLen)
				var ip = string(payload.Next(int(ipLen)))
				var port uint32
				binary.Read(payload, binary.BigEndian, &port)
				var addr = net.TCPAddr{IP: net.ParseIP(ip), Port: int(port)}
				var ln, _ = cli.lns.Load(addr.String())
				var ch, _, _ = ch.Accept()
				ln.(chan ssh.Channel) <- ch
			}
		}
	}()
	return cli
}
func (c *Client) Shell() ssh.Channel {
	var ch, reqs, _ = c.OpenChannel("session", nil)
	ch.SendRequest("shell", false, nil)
	go func() {
		for req := range reqs {
			if req.Type == "exit-status" {
				ch.Close()
			}
		}
	}()
	return ch
}
func (c *Client) Dial(addr string) ssh.Channel {
	var payload = bytes.NewBuffer(nil)
	var host, portString, _ = net.SplitHostPort(addr)
	var rAddr = net.ParseIP(host).To4().String()
	var rPort, _ = strconv.Atoi(portString)
	binary.Write(payload, binary.BigEndian, uint32(len(rAddr)))
	payload.WriteString(rAddr)
	binary.Write(payload, binary.BigEndian, uint32(rPort))
	binary.Write(payload, binary.BigEndian, uint32(7))
	payload.WriteString("0.0.0.0")
	binary.Write(payload, binary.BigEndian, uint32(0))
	var ch, _, _ = c.OpenChannel("direct-tcpip", payload.Bytes())
	return ch
}
func (c *Client) Listen(addr string) <-chan ssh.Channel {
	var payload = bytes.NewBuffer(nil)
	var host, portString, _ = net.SplitHostPort(addr)
	var port, _ = strconv.Atoi(portString)
	binary.Write(payload, binary.BigEndian, uint32(len(host)))
	payload.WriteString(host)
	binary.Write(payload, binary.BigEndian, uint32(port))
	c.SendRequest("tcpip-forward", false, payload.Bytes())
	var ln, _ = c.lns.LoadOrStore(addr, make(chan ssh.Channel))
	return ln.(chan ssh.Channel)
}
