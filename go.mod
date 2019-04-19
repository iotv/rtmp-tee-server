module github.com/iotv/rtmp-tee-server

require (
	github.com/iotv/rtmp-tee-server/amf v0.0.0
	github.com/iotv/rtmp-tee-server/rtmp v0.0.0
)

replace (
	github.com/iotv/rtmp-tee-server/amf => ./amf
	github.com/iotv/rtmp-tee-server/rtmp => ./rtmp
)

go 1.12
