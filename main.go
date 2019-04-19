package main

import (
	"github.com/iotv/rtmp-tee-server/rtmp"
)

func main() {
	server := rtmp.Server{}
	_ = server.ListenAndServe()
}
