package snet

// NotFragmented is used by our github.com/anapaya/quic-go fork to enable
// path MTU discovery even if the connection is not a net.UDPConn.
func (*Conn) NotFragmented() {}
