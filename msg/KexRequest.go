package msg

type KexRequest struct {
	PubKey []byte `sshtype:"30"`
}
