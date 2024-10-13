package msg

type ChannelOpen struct {
	ChanType         string `sshtype:"90"`
	LocalID          uint32
	LocalWindow      uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}
