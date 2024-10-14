package msg

type ChannelOpen struct {
	ChanType      string `sshtype:"90"`
	Src           uint32
	WindowSize    uint32
	MaxPacketSize uint32
	Payload       []byte `ssh:"rest"`
}
