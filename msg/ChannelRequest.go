package msg

type ChannelRequest struct {
	PeersID   uint32 `sshtype:"98"`
	Request   string
	WantReply bool
}
