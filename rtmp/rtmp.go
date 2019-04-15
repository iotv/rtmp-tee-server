package rtmp

import (
	"time"
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation
type contextKey struct {
	name string
}

// getUint32MilsTimestamp returns a millisecond uint32 timestamp
// time.Nanosecond should be 1, making this a trivial function so long as
// the uint32 cast is done after converting a int64 to milliseconds, however
// it is advised to multiply by the constant in the event that golang increases
// time resolution.
func getUint32MilsTimestamp() uint32 {
	return uint32(((time.Now().UnixNano() * int64(time.Nanosecond)) / int64(time.Millisecond)) % int64(^uint32(0)))
}
