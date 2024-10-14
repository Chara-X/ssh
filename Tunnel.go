package tunnel

import (
	"math/rand"
	"net"
	"os"
	"strconv"

	"github.com/Chara-X/tunnel/msg"
	"golang.org/x/crypto/ssh"
)

type Tunnel struct{ c *Conn }

func New(conn *Conn) *Tunnel { return &Tunnel{c: conn} }
func (t *Tunnel) Shell() *Channel {
	var ch = t.open("session", nil)
	t.c.Send(&msg.ChannelRequest{RemoteID: ch.RemoteID, Request: "shell"})
	return ch
}
func (t *Tunnel) Dial(address string) *Channel {
	var ip, portString, _ = net.SplitHostPort(address)
	var port, _ = strconv.Atoi(portString)
	var ch = t.open("direct-tcpip", ssh.Marshal(struct {
		RAddr string
		RPort uint32
		LAddr string
		LPort uint32
	}{RAddr: ip, RPort: uint32(port), LAddr: "0.0.0.0"}))
	return ch
}
func (t *Tunnel) open(name string, data []byte) *Channel {
	var ch = &Channel{c: t.c, ch: make(chan interface{}, 1024), LocalID: rand.Uint32()}
	ch.pipeR, ch.pipeW, _ = os.Pipe()
	t.c.chs.Store(ch.LocalID, ch)
	t.c.Send(&msg.ChannelOpen{ChanType: name, LocalID: ch.LocalID, LocalWindow: 1024, MaxPacketSize: 1024, TypeSpecificData: data})
	ch.RemoteID = (<-ch.ch).(*msg.ChannelOpenConfirm).LocalID
	return ch
}
