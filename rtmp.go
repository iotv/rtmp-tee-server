package rtmp

import (
	"time"
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation
type contextKey struct {
	name string
}

func getUint32MilsTimestamp() uint32 {
	return uint32(((time.Now().UnixNano() * int64(time.Nanosecond)) / int64(time.Millisecond)) % int64(^uint32(0)))
}
