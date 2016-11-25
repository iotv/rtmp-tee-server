package rtmp

import (
	"context"
	"net"
)

type conn struct {
	server *Server
	rwc    net.Conn
}

func (c *conn) handshake() error {
	return nil
}

func (c *conn) serve(ctx context.Context) {
}
