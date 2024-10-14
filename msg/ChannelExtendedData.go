package msg

type ChannelExtendedData struct {
	RemoteID uint32 `sshtype:"95"`
	Code     uint32
	Data     string
}
