package tunnel

import (
	"os"

	"github.com/Chara-X/tunnel/msg"
)

type Channel struct {
	pipeR, pipeW *os.File
	ch           chan interface{}
	c            *Conn
	LocalID      uint32
	RemoteID     uint32
}

func (ch *Channel) Read(data []byte) (int, error) { return ch.pipeR.Read(data) }
func (ch *Channel) Write(data []byte) (int, error) {
	ch.c.Send(&msg.ChannelData{RemoteID: ch.RemoteID, Data: string(data)})
	return len(data), nil
}
func (ch *Channel) Close() {
	ch.c.chs.Delete(ch.LocalID)
	ch.pipeR.Close()
	close(ch.ch)
}
