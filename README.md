# tunnel

## Example

```go
var config = &tunnel.Config{
	User:     "root",
	Password: "123",
}
func ExampleShell() {
	var conn, _ = net.Dial("tcp", "192.168.58.2:30631")
	defer conn.Close()
	var t = tunnel.New(conn, config)
	var c = t.Open(&msg.ChannelOpen{ChanType: tunnel.Session, WindowSize: 1024, MaxPacketSize: 1024})
	go func() {
		io.Copy(os.Stdout, c)
	}()
	io.Copy(c, os.Stdin)
}
```

```go
func ExampleDirect() {
	var conn, _ = net.Dial("tcp", "192.168.58.2:30631")
	defer conn.Close()
	var t = tunnel.New(conn, config)
	var ln, _ = net.Listen("tcp", "127.0.0.1:8080")
	defer ln.Close()
	for {
		var conn, _ = ln.Accept()
		go func() {
			var c = t.Open(&msg.ChannelOpen{ChanType: tunnel.Direct, WindowSize: 1024, MaxPacketSize: 1024, Payload: ssh.Marshal(struct {
				RAddr string
				RPort uint32
				LAddr string
				LPort uint32
			}{RAddr: "127.0.0.1", RPort: 80, LAddr: "0.0.0.0"})})
			go io.Copy(c, conn)
			io.Copy(conn, c)
		}()
	}
}
```

## Reference

[The Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253)
[The Secure Shell (SSH) Authentication Protocol](https://datatracker.ietf.org/doc/html/rfc4252)
[The Secure Shell (SSH) Connection Protocol](https://datatracker.ietf.org/doc/html/rfc4254)
