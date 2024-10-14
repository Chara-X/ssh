package msg

type ChannelEOF struct {
	RemoteID uint32 `sshtype:"96"`
}
