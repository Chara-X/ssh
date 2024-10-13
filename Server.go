package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type Server struct{ cfg *ssh.ServerConfig }

func NewServer(cfg *ssh.ServerConfig) *Server { return &Server{cfg} }
func (s *Server) ListenAndServe(addr string) {
	var ln, _ = net.Listen("tcp", addr)
	for {
		var conn, _ = ln.Accept()
		var cli = &Client{}
		var chs = make(<-chan ssh.NewChannel)
		var reqs = make(<-chan *ssh.Request)
		cli.Conn, chs, reqs, _ = ssh.NewServerConn(conn, s.cfg)
		go func() {
			for ch := range chs {
				go func() {
					fmt.Println("ChannelType:", ch.ChannelType())
					switch ch.ChannelType() {
					case "session":
						var ch, reqs, _ = ch.Accept()
						AcceptRequests(reqs)
						var cmd = exec.Command("bash")
						cmd.Stdin, cmd.Stdout = ch, ch
						cmd.Run()
					case "direct-tcpip":
						var payload = bytes.NewBuffer(ch.ExtraData())
						var ipLen uint32
						binary.Read(payload, binary.BigEndian, &ipLen)
						var ip = string(payload.Next(int(ipLen)))
						var port uint32
						binary.Read(payload, binary.BigEndian, &port)
						var ch, _, _ = ch.Accept()
						var conn, _ = net.Dial("tcp", ip+":"+strconv.Itoa(int(port)))
						go func() {
							defer conn.Close()
							defer ch.Close()
							go io.Copy(conn, ch)
							io.Copy(ch, conn)
						}()
					}
				}()
			}
		}()
		go func() {
			for req := range reqs {
				if req.WantReply {
					req.Reply(true, nil)
				}
				switch req.Type {
				case "tcpip-forward":
					var payload = bytes.NewBuffer(req.Payload)
					var ipLen uint32
					binary.Read(payload, binary.BigEndian, &ipLen)
					var ip = string(payload.Next(int(ipLen)))
					var port uint32
					binary.Read(payload, binary.BigEndian, &port)
					var ln, _ = net.Listen("tcp", ip+":"+strconv.Itoa(int(port)))
					go func() {
						for {
							var conn, _ = ln.Accept()
							var payload = bytes.NewBuffer(req.Payload)
							binary.Write(payload, binary.BigEndian, uint32(7))
							payload.WriteString("0.0.0.0")
							binary.Write(payload, binary.BigEndian, uint32(0))
							var ch, _, err = cli.OpenChannel("forwarded-tcpip", payload.Bytes())
							fmt.Println(err)
							go func() {
								defer conn.Close()
								defer ch.Close()
								go io.Copy(conn, ch)
								io.Copy(ch, conn)
							}()
						}
					}()
				}
			}
		}()
	}
}
