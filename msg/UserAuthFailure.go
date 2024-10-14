package msg

type UserAuthFailure struct {
	Methods        []string `sshtype:"51"`
	PartialSuccess bool
}
