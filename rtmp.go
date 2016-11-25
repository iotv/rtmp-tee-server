package rtmp

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation
type contextKey struct {
	name string
}
