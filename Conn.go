package tunnel

import (
	"os"

	"github.com/Chara-X/tunnel/msg"
)

type Conn struct {
	tunnel       *Tunnel
	pipeR, pipeW *os.File
	ch           chan interface{}
	LocalID      uint32
	RemoteID     uint32
}

func (c *Conn) Read(data []byte) (int, error) { return c.pipeR.Read(data) }
func (c *Conn) Write(data []byte) (int, error) {
	c.tunnel.Send(&msg.ChannelData{RemoteID: c.RemoteID, Data: string(data)})
	return len(data), nil
}
