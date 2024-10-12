package msg

type UserAuthBanner struct {
	Message string `sshtype:"53"`
	// unused, but required to allow message parsing
	Language string
}
