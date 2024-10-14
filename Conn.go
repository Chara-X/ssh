package tunnel

import (
	"os"

	"github.com/Chara-X/tunnel/msg"
)

type Conn struct {
	pipeR, pipeW *os.File
	ch           chan interface{}
	t            *Mux
	Src, Dst     uint32
}

func (c *Conn) Read(data []byte) (int, error) { return c.pipeR.Read(data) }
func (c *Conn) Write(data []byte) (int, error) {
	c.t.Encode(&msg.ChannelData{RemoteID: c.Dst, Data: string(data)})
	return len(data), nil
}
func (c *Conn) Close() {
	c.t.cs.Delete(c.Src)
	c.pipeR.Close()
	close(c.ch)
}
