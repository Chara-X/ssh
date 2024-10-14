package main

import (
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Chara-X/tunnel"
	"github.com/Chara-X/tunnel/msg"
	"golang.org/x/crypto/ssh"
)

// tunnel 196.128.0.1 root:123 shell
// tunnel 196.128.0.1 root:123 forward 8080 127.0.0.1:80
func main() {
	var conn, _ = net.Dial("tcp", os.Args[1])
	defer conn.Close()
	var t = tunnel.New(conn, &tunnel.Config{User: strings.Split(os.Args[2], ":")[0], Password: strings.Split(os.Args[2], ":")[1]})
	switch os.Args[3] {
	case tunnel.Shell:
		var c = t.Open(&msg.ChannelOpen{ChanType: tunnel.Session, WindowSize: 1024, MaxPacketSize: 1024})
		defer c.Close()
		go func() {
			io.Copy(os.Stdout, c)
		}()
		io.Copy(c, os.Stdin)
	case tunnel.Direct:
		var ln, _ = net.Listen("tcp", os.Args[4])
		defer ln.Close()
		for {
			var conn, _ = ln.Accept()
			go func() {
				defer conn.Close()
				var ip, portString, _ = net.SplitHostPort(os.Args[5])
				var port, _ = strconv.Atoi(portString)
				var c = t.Open(&msg.ChannelOpen{ChanType: tunnel.Direct, WindowSize: 1024, MaxPacketSize: 1024, Payload: ssh.Marshal(struct {
					RAddr string
					RPort uint32
					LAddr string
					LPort uint32
				}{RAddr: ip, RPort: uint32(port), LAddr: "0.0.0.0"})})
				defer c.Close()
				go io.Copy(c, conn)
				io.Copy(conn, c)
			}()
		}
	}
}
