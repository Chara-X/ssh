package tunnel

import (
	"os"

	"github.com/Chara-X/tunnel/msg"
)

type Conn struct {
	tunnel       *Tunnel
	ch           chan interface{}
	pipeR, pipeW *os.File
	LocalID      uint32
	RemoteID     uint32
}

func (c *Conn) Recv() interface{} { return <-c.ch }
func (c *Conn) Send(name string, data []byte) {
	c.tunnel.Send(&msg.ChannelRequest{PeersID: c.RemoteID, Request: name, WantReply: false, RequestSpecificData: data})
}
func (c *Conn) Read(data []byte) (int, error) { return c.pipeR.Read(data) }
func (c *Conn) Write(data []byte) (int, error) {
	c.tunnel.Send(&msg.ChannelData{RemoteID: c.RemoteID, Data: string(data)})
	return len(data), nil
}
