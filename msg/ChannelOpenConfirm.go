package msg

type ChannelOpenConfirm struct {
	PeersID          uint32 `sshtype:"91"`
	MyID             uint32
	MyWindow         uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}
