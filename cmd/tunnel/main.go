package main

import (
	"io"
	"net"
	"os"
	"strings"

	"github.com/Chara-X/tunnel"
)

func main() {
	var c = tunnel.Connect("tcp", os.Args[1], &tunnel.Config{User: strings.Split(os.Args[2], ":")[0], Password: strings.Split(os.Args[2], ":")[1]})
	defer c.Close()
	var t = tunnel.New(c)
	switch os.Args[3] {
	case "shell":
		var c = t.Shell()
		defer c.Close()
		go func() {
			io.Copy(os.Stdout, c)
		}()
		io.Copy(c, os.Stdin)
	case "forward":
		var ln, _ = net.Listen("tcp", strings.Split(os.Args[4], ":")[0])
		defer ln.Close()
		for {
			var conn, _ = ln.Accept()
			go func() {
				defer conn.Close()
				var c = t.Dial(strings.Split(os.Args[4], ":")[1])
				defer c.Close()
				go io.Copy(c, conn)
				io.Copy(conn, c)
			}()
		}
	}
}
