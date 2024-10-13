package tunnel

import "golang.org/x/crypto/ssh"

func AcceptRequests(in <-chan *ssh.Request) {
	for req := range in {
		if req.WantReply {
			req.Reply(true, nil)
		}
	}
}
