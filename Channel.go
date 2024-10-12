package ssh

import (
	"encoding/binary"
	"os"

	"github.com/Chara-X/ssh/msg"
)

type Channel struct {
	id         uint32
	chanType   string
	conn       *Conn
	bufR, bufW os.File
}

func (c *Channel) Read(data []byte) (int, error) { return c.bufR.Read(data) }
func (c *Channel) Write(data []byte) (int, error) {
	var packet = make([]byte, len(data)+9)
	packet[0] = MsgChannelData
	binary.BigEndian.PutUint32(packet[1:], c.id)
	binary.BigEndian.PutUint32(packet[5:], uint32(len(data)))
	copy(packet[9:], data)
	c.conn.WritePacket(packet)
	return len(data), nil
}
func (c *Channel) SendRequest(name string, payload []byte) error {
	if err := c.conn.WriteCipherPacket(msg.ChannelRequest{
		PeersID:             c.id,
		Request:             name,
		WantReply:           false,
		RequestSpecificData: payload,
	}); err != nil {
		panic(err)
	}
	return nil
}
