package msg

type ChannelRequest struct {
	RemoteID            uint32 `sshtype:"98"`
	Request             string
	WantReply           bool
	RequestSpecificData []byte `ssh:"rest"`
}
