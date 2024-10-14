package tunnel

var (
	HostKeyAlgorithms = []string{"ecdsa-sha2-nistp256"}
	KeyExchanges      = []string{"ecdh-sha2-nistp256"}
	Ciphers           = []string{"aes256-ctr"}
	MACs              = []string{"hmac-sha2-256"}
	Compression       = []string{"none"}
)
var (
	ClientVersion = []byte("SSH-2.0-Go")
)
