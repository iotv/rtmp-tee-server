package rtmp

import (
  "net"
)

type Conn struct {
  TCPConn *net.TCPConn
}

func NewConn(tcpConn *net.TCPConn) (*Conn, error) {
  conn := &Conn{
    TCPConn: tcpConn,
  }
  return conn, nil
}

func (c *Conn) Handshake() error {
  
}
