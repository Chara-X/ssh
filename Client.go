package ssh

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type Client struct{ *Conn }

func NewClient(addr string, cfg *ssh.ClientConfig) *Client {
	var conn, _ = net.Dial("tcp", addr)
	var cli = &Client{Conn: NewConn(conn, cfg)}
	return cli
}
func (c *Client) Shell() *Channel {
	var ch = c.OpenChannel("session", nil)
	ch.SendRequest("shell", nil)
	return ch
}
func (c *Client) Dial(addr string) *Channel {
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
	return c.OpenChannel("direct-tcpip", payload.Bytes())
}
