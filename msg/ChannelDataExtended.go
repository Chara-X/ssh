package msg

type ChannelDataExtended struct {
	RemoteID uint32 `sshtype:"95"`
	Code     uint32
	Data     string
}
