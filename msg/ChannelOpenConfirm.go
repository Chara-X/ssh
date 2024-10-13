package msg

type ChannelOpenConfirm struct {
	RemoteID      uint32 `sshtype:"91"`
	LocalID       uint32
	Window        uint32
	MaxPacketSize uint32
}
