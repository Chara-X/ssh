package msg

type ChannelData struct {
	RemoteID uint32 `sshtype:"94"`
	Data     string
}
