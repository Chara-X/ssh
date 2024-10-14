package msg

type ChannelOpenConfirm struct {
	Dst           uint32 `sshtype:"91"`
	Src           uint32
	Window        uint32
	MaxPacketSize uint32
}
