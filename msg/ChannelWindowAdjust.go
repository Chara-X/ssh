package msg

type ChannelWindowAdjust struct {
	RemoteID        uint32 `sshtype:"93"`
	AdditionalBytes uint32
}
