package msg

type ChannelOpen struct {
	ChanType         string `sshtype:"90"`
	PeersID          uint32
	PeersWindow      uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}
