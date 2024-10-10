package msg

type KexReply struct {
	HostKey   []byte `sshtype:"31"`
	PubKey    []byte
	Signature []byte
}
