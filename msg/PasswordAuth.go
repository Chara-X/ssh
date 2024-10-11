package msg

type PasswordAuth struct {
	User     string `sshtype:"50"`
	Service  string
	Method   string
	Reply    bool
	Password string
}
