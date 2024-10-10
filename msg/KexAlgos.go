package msg

type KexAlgos struct {
	Cookie                  [16]byte `sshtype:"20"`
	KexAlgos                []string
	ServerHostKeyAlgos      []string
	CiphersClientServer     []string
	CiphersServerClient     []string
	MACsClientServer        []string
	MACsServerClient        []string
	CompressionClientServer []string
	CompressionServerClient []string
	LanguagesClientServer   []string
	LanguagesServerClient   []string
	FirstKexFollows         bool
	Reserved                uint32
}
