package rtmp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/iotv/rtmp-tee-server/amf"
)

type chunkHeaderType uint8

const (
	type0 chunkHeaderType = iota
	type1
	type2
	type3
)

type chunkBasicHeader struct {
	ChunkMessageHeaderFormat chunkHeaderType
	ChunkStreamId            uint32
}

func (c *conn) receiveChunkBasicHeader(ctx context.Context) (*chunkBasicHeader, error) {
	// FIXME: debug log this
	basicHeaderType, err := c.bufr.Peek(1)
	if err != nil {
		// FIXME
		return nil, err
	}
	var basicHeaderLen int
	// Apply a "bit clear" (AND NOT) to bit mask 0b11000000, removing the chunk format
	switch basicHeaderType[0] &^ 0xC0 {
	// 0bXX000000 indicates a 2 byte basic header
	case 0x00:
		basicHeaderLen = 2
	// 0bXX000001 indicates a 3 byte basic header
	case 0x01:
		basicHeaderLen = 3
	// The default is a 1 byte header where 0b00111111 is the chunk stream id mask
	default:
		basicHeaderLen = 1
	}

	// FIXME: use a pool
	basicHeader := make([]byte, basicHeaderLen)

	// Read basic header for the chunk
	if bHLen, err := io.ReadFull(c.bufr, basicHeader); bHLen != basicHeaderLen {
		return nil, fmt.Errorf("rtmp: read basic header failed: expected %d len header, got: %d", basicHeaderLen, bHLen)
	} else if err != nil {
		return nil, fmt.Errorf("rtmp: read chunk basic header failed: %s", err.Error())
	}

	// read fmt from first 2 bits and move them from the most significant bits to the least significant bits
	chunkHeaderFormat := (basicHeader[0] & 0xC0) >> 6

	// get stream id as a uint32 by masking off unused bits and padding the front with 0's
	basicHeader[0] = basicHeader[0] &^ 0xC0
	var streamId uint32 = 0
	switch basicHeaderLen {
	case 1:
		streamId += uint32(basicHeader[0])
	case 2:
		// Chunk stream IDs 64-319 can be encoded in the 2-byte form of the
		// header. ID is computed as (the second byte + 64).
		streamId += uint32(basicHeader[1]) + 64
	default: // 3
		//  stream IDs 64-65599 can be encoded in the 3-byte version of
		// this field. ID is computed as ((the third byte)*256 + (the second
		// byte) + 64)
		streamId += (uint32(basicHeader[2]) * 256) + 64
	}

	if basicHeaderLen == 2 || basicHeaderLen == 3 {
		streamId += 64 // 2 and 3 byte headers exclude IDs 2-63. It's ghetto. It's RTMP.
	}
	return &chunkBasicHeader{
			ChunkMessageHeaderFormat: chunkHeaderType(chunkHeaderFormat),
			ChunkStreamId:            streamId,
		},
		nil
}

func (c *conn) receiveChunkMessageHeader(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (c *conn) receiveChunkExtendedTimestamp(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (c *conn) receiveChunkHeader(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (c *conn) receiveChunkData(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (c *conn) receiveChunk(ctx context.Context) ([]byte, error) {
	basicHeader, err := c.receiveChunkBasicHeader(ctx)

	// Chunk Message header
	switch basicHeader.ChunkMessageHeaderFormat {
	case type0:
		err = c.readType0MessageHeader()
	case type1:
		err = c.readType1MessageHeader()
	case type2:
		err = c.readType2MessageHeader()
	default: // implied type 3 header
		err = c.verifyType3MessageHeader()
	}
	if err != nil {
		return nil, fmt.Errorf("rtmp: receive chunk failed: %s", err.Error())
	}

	// FIXME: do not allocate memory based on a network peer's demands. set a limit and obey it
	message := make([]byte, *c.prvIncMsgLen)
	c.bufr.Read(message)

	switch *c.prvIncMsgTypId {
	case 20: // AMF0 command message
		// write a user result amf0
		amf0 := &amf.AMF0Msg{}
		if err := amf0.UnmarshalBinary(message); err != nil {
			return nil, err
		}
		v, ok := (*amf0)[0]
		if !ok {
			fmt.Println("Tots bonkers message. ---")
		} else {
			switch v {
			case "connect":
				c.writeAMF0NetConnectionConnectSuccess()
			case "FCPublish":
				f := (*amf0)[1].(float64)
				c.writeAMF0FCPublishSuccess(f)
			case "releaseStream":
				f := (*amf0)[1].(float64)
				c.writeAMF0ReleaseStreamSuccess(f)
			case "createStream":
				f := (*amf0)[1].(float64)
				c.writeAMF0CreateStreamSuccess(f)
			case "publish":
				f := (*amf0)[1].(float64)
				c.writeAMF0CreateStreamSuccess(f)
			}
		}
	}
	return nil, nil
}

func (c *conn) readType0MessageHeader() error {
	now := time.Now()

	header := make([]byte, 11)
	if hLen, err := c.bufr.Read(header); hLen != 11 {
		return fmt.Errorf("rtmp: read message header failed: expected 11 len header, got: %d", hLen)
	} else if err != nil {
		return fmt.Errorf("rtmp: read message header failed: %s", err.Error())
	}

	msgTs := binary.BigEndian.Uint32(append([]byte{0}, header[0:3]...))
	// FIXME: handle extended timestamp

	msgLen := binary.BigEndian.Uint32(append([]byte{0}, header[3:6]...))
	msgTypId := uint8(header[6])
	msgStrmId := binary.BigEndian.Uint32(header[7:])

	c.prvIncMsgTime = &now
	c.prvIncMsgTs = &msgTs
	c.prvIncMsgLen = &msgLen
	c.prvIncMsgTypId = &msgTypId
	c.prvIncMsgStrmId = &msgStrmId

	return nil
}

func (c *conn) readType1MessageHeader() error {
	if c.prvIncMsgStrmId == nil {
		return errors.New("rtmp: cannot read type 1 message header if no previous type 0 has been sent with stream id")
	}
	if c.prvIncMsgTs == nil {
		return errors.New("rtmp: cannot read type 1 message header if no previous type 0, has been sent with message timestamp")
	}

	now := time.Now()

	header := make([]byte, 7)
	if hLen, err := c.bufr.Read(header); hLen != 7 {
		return fmt.Errorf("rtmp: read message header failed")
	} else if err != nil {
		return fmt.Errorf("rtmp: read message header failed: %s", err.Error())
	}

	msgTsD := binary.BigEndian.Uint32(append([]byte{0}, header[0:3]...))
	msgTs := (*c.prvIncMsgTs + msgTsD) % 0x01000000 // keep it to 3 bytes by rolling it
	// FIXME: handle extended timestamp

	msgLen := binary.BigEndian.Uint32(append([]byte{0}, header[3:6]...))
	msgTypId := uint8(header[6])

	c.prvIncMsgTime = &now
	c.prvIncMsgTsD = &msgTsD
	c.prvIncMsgTs = &msgTs
	c.prvIncMsgLen = &msgLen
	c.prvIncMsgTypId = &msgTypId

	return nil
}

func (c *conn) readType2MessageHeader() error {
	if c.prvIncMsgStrmId == nil {
		return errors.New("rtmp: cannot read type 2 message header if no previous type 0 has been sent with stream id")
	}
	if c.prvIncMsgTs == nil {
		return errors.New("rtmp: cannot read type 2 message header if no previous type 0, has been sent with message timestamp")
	}
	if c.prvIncMsgLen == nil {
		return errors.New("rtmp: cannot read type 2 message header if no previous type 0,1 has been sent with message length")
	}
	if c.prvIncMsgTypId == nil {
		return errors.New("rtmp: cannot read type 2 message header if no previous type 0,1 has been sent with message type id")
	}

	now := time.Now()

	header := make([]byte, 3)
	if hLen, err := c.bufr.Read(header); hLen != 3 {
		return errors.New("rtmp: read message header failed")
	} else if err != nil {
		return fmt.Errorf("rtmp: read message header failed: %s", err.Error())
	}

	msgTsD := binary.BigEndian.Uint32(append([]byte{0}, header[0:3]...))
	msgTs := (*c.prvIncMsgTs + msgTsD) % 0x01000000 // keep it to 3 bytes by rolling it
	// FIXME: handle extended timestamp

	c.prvIncMsgTime = &now
	c.prvIncMsgTsD = &msgTsD
	c.prvIncMsgTs = &msgTs

	return nil
}

func (c *conn) verifyType3MessageHeader() error {
	if c.prvIncMsgStrmId == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 0 has been sent with stream id")
	}
	if c.prvIncMsgTs == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 0, has been sent with message timestamp")
	}
	if c.prvIncMsgLen == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 0,1 has been sent with message length")
	}
	if c.prvIncMsgTypId == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 0,1 has been sent with message type id")
	}
	if c.prvIncMsgTsD == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 1,2 has been sent with message timestamp delta")
	}

	now := time.Now()

	msgTs := (*c.prvIncMsgTs + *c.prvIncMsgTsD) % 0x01000000 // keep it to 3 bytes by rolling it

	c.prvIncMsgTime = &now
	c.prvIncMsgTs = &msgTs

	return nil
}

// FIXME: parametrize variables
func (c *conn) writeWindowSizeAcknowledgementChunk() error {
	// write a window size acknowledgement chunk
	c.writeChunkBasicHeader(0, 2)
	c.writeType0ChunkMessageHeader(0, 4, 5, 0, 2)
	c.bufw.Write([]byte{0, 0, 250, 0})
	c.bufw.Flush()
	return nil
}

// FIXME: parameterize variables
func (c *conn) writeSetPeerBandwidthChunk() error {
	// set bandwidth
	c.writeChunkBasicHeader(0, 2)
	c.writeType0ChunkMessageHeader(0, 5, 6, 0, 2)
	c.bufw.Write([]byte{0, 5, 0, 0, 0})
	c.bufw.Flush()
	return nil
}

// FIXME: figure out if this is even needed. extract parameters
func (c *conn) writeRTMPStartStreamMessage() error {
	// write this terrible rtmp start stream thing
	c.writeChunkBasicHeader(0, 2)
	c.writeType0ChunkMessageHeader(0, 17, 4, 0, 2)
	c.bufw.Write([]byte{4})       // rtmp message type???
	c.bufw.Write([]byte{0, 0, 6}) // payload length
	whocares := make([]byte, 4)
	binary.BigEndian.PutUint32(whocares, getUint32MilsTimestamp())
	c.bufw.Write(whocares)
	c.bufw.Write([]byte{0, 0, 0})          // stream id 0?
	c.bufw.Write([]byte{0, 0, 0, 0, 0, 0}) // ?? Stream begin. Stream 0?
	c.bufw.Flush()
	return nil
}

// writeChunkBasicHeader writes the first bytes of a chunk which is the
// chunk basic header. The chunk basic header identifies the chunk stream id
// and the following message format. A chunk basic header has a length based
// on the chunk stream id.
// In the RTMP spec the parameters map as follow:
//    format => fmt (this is a library used here)
//    chunkStreamId => cs id
func (c *conn) writeChunkBasicHeader(format uint8, chunkStreamId uint32) error {
	if format > 3 {
		return errors.New("rtmp: failed to write chunk basic header: format larger than 2 bits")
	}
	if chunkStreamId > 65599 {
		return errors.New("rtmp: failed to write chunk basic header: chunk stream id greater than max")
	} else if chunkStreamId < 2 {
		return errors.New("rtmp: failed to write chunk basic header: chunk stream id less than min")
	}

	// Set fmt bits to first 2 bits of MSB
	fmtBits := byte(0)
	switch format {
	case 0:
		fmtBits = 0x00
	case 1:
		fmtBits = 0x40
	case 2:
		fmtBits = 0x80
	case 3:
		fmtBits = 0xC0
	default: // This shouldn't be reachable
		return fmt.Errorf("rtmp: failed to write chunk basic header: invalid fmt: %d", format)
	}

	csBytes := make([]byte, 4)

	// Write the byte representation of chunk stream header
	switch {
	case 2 <= chunkStreamId && chunkStreamId < 64:
		binary.BigEndian.PutUint32(csBytes, chunkStreamId)
		csBytes[3] = (csBytes[3] &^ 0xC0) | fmtBits // clear bits then write fmtBits
		c.bufw.Write(csBytes[3:4])                  // write only the least significant 1 byte
	case 64 <= chunkStreamId && chunkStreamId < 320:
		binary.BigEndian.PutUint32(csBytes, chunkStreamId-64)
		csBytes[2] = (csBytes[2] &^ 0xC0) | fmtBits // clear bits then write fmtBits
		c.bufw.Write(csBytes[2:4])                  // write only the least significant 2 bytes
	case 320 <= chunkStreamId && chunkStreamId < 65599:
		binary.BigEndian.PutUint32(csBytes, chunkStreamId-64)
		csBytes[1] = (csBytes[1] &^ 0xC0) | fmtBits | 0x01 // clear bits then write fmtBits + 1 to signal 3 byte message
		c.bufw.Write(csBytes[1:4])                         // write only the least significant 3 bytes
	default: // This shouldn't be reachable
		return fmt.Errorf("rtmp: failed to write chunk basic header: invalid id: %d", chunkStreamId)
	}

	return nil
}

func (c *conn) writeChunkMessageHeader() error {
	return nil
}

func (c *conn) writeType0ChunkMessageHeader(ts uint, msgLen uint32, msgType uint8, msgStrmId, chunkStreamId uint32) error {
	// TODO: see if this is legal without updating the client epoch
	if ts > 0xFFFFFF { // Despite being > 4 bytes, it must fit in 3
		ts = ts % 0x01000000 // roll the timestamp.
	}

	if msgLen > 0xFFFFFF { // Despite being 4 bytes, it must fit in 3
		return fmt.Errorf("rtmp: failed to write type 0 chunk message header: message length too large: %d", msgLen)
	}

	// TODO: maybe DGAF about this?
	// Check if msgType is part of messages we know about
	switch msgType {
	case 1, 2, 3, 4, 5, 6:
		// RTMP Spec says message stream id must be 0 for stream control messages
		if msgStrmId != 0 {
			return fmt.Errorf("rtmp: failed to write type 0 chunk message header: message stream id must be 0 but was: %d", msgStrmId)
		}

		// RTMP Spec says chunk stream id must be 2 for stream control messages
		// FIXME: it's a little late to catch this error... might need to fix where
		// we check this or recover by finishing writing a blank message
		if chunkStreamId != 2 {
			return fmt.Errorf("rtmp: failed to write type 0 chunk message header: chunk stream id must be 2 but was: %d", chunkStreamId)
		}
	case 8, 9, 15, 16, 17, 18, 19, 20, 22:
		// we recognize this. ensure the chunk stream id isn't the control stream or weird
		// chunk stream id 0 and 1 are formatting reserved.
		// FIXME: it's a little late to catch this error... might need to fix where
		// we check this or recover by finishing writing a blank message
		if chunkStreamId < 2 {
			return fmt.Errorf("rtmp: failed to write type 0 chunk message header: Invalid chunk stream id: %d", chunkStreamId)
		} else if chunkStreamId == 2 { // 2 is reserved for types 1-6
			return fmt.Errorf("rtmp: failed to write type 0 chunk message header: chunk stream id 2 is reserved for protocol control")
		}
		// It all looks good. do nothing
	default:
		return fmt.Errorf("rtmp: failed to write type 0 chunk message header: msgType not recognized: %d", msgType)
	}

	// TODO: get some pooling going
	tsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tsBytes, uint32(ts)) // we modulo'd above so truncate should have no effect

	msgLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLenBytes, msgLen)

	msgStrmIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(msgStrmIdBytes, msgStrmId)

	// TODO: is this the best I can do?
	messageHeader := append([]byte{}, tsBytes[1:]...)
	messageHeader = append(messageHeader, msgLenBytes[1:]...)
	messageHeader = append(messageHeader, byte(msgType))
	messageHeader = append(messageHeader, msgStrmIdBytes...)

	if mHLen, err := c.bufw.Write(messageHeader); mHLen != 11 || err != nil {
		return fmt.Errorf("rtmp: failed to write type 0 chunk message header: %s", err.Error())
	}
	return nil
}

func (c *conn) writeType1ChunkMessageHeader() error {
	return nil
}

func (c *conn) writeType2ChunkMessageHeader() error {
	return nil
}

func (c *conn) writeType3ChunkMessageHeader() error {
	return nil
}

func (c *conn) writeAMF0PublishSuccess(tId float64) error {
	msg := &amf.AMF0Msg{
		0: "_result",
		1: tId,
		2: amf.AMF0Object{},
		3: amf.AMF0Object{
			"level": "status",
			"code":  "NetConnection.Connect.Success",
		},
	}
	b, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	if len(b) > 0xFFFFFF {
		return errors.New("rtmp: AMF0 message too large")
	}

	c.writeChunkBasicHeader(0, 2)
	c.writeType0ChunkMessageHeader(0, uint32(len(b)), 20, 0, 2)
	c.bufw.Write(b)
	c.bufw.Flush()
	return nil
}

func (c *conn) writeAMF0FCPublishSuccess(tId float64) error {
	msg := &amf.AMF0Msg{
		0: "_result",
		1: tId,
		2: amf.AMF0Object{},
		3: amf.AMF0Object{
			"level": "status",
			"code":  "NetConnection.Connect.Success",
		},
	}
	b, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	if len(b) > 0xFFFFFF {
		return errors.New("rtmp: AMF0 message too large")
	}

	c.writeChunkBasicHeader(0, 2)
	c.writeType0ChunkMessageHeader(0, uint32(len(b)), 20, 0, 2)
	c.bufw.Write(b)
	c.bufw.Flush()
	return nil
}

func (c *conn) writeAMF0CreateStreamSuccess(tId float64) error {
	msg := &amf.AMF0Msg{
		0: "_result",
		1: tId,
		2: amf.AMF0Object{},
		3: amf.AMF0Object{
			"level": "status",
			"code":  "NetConnection.Connect.Success",
		},
	}
	b, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	if len(b) > 0xFFFFFF {
		return errors.New("rtmp: AMF0 message too large")
	}

	c.writeChunkBasicHeader(0, 2)
	c.writeType0ChunkMessageHeader(0, uint32(len(b)), 20, 0, 2)
	c.bufw.Write(b)
	c.bufw.Flush()
	return nil
}

func (c *conn) writeAMF0ReleaseStreamSuccess(tId float64) error {
	msg := &amf.AMF0Msg{
		0: "_result",
		1: tId,
		2: amf.AMF0Object{},
		3: amf.AMF0Object{
			"level": "status",
			"code":  "NetConnection.Connect.Success",
		},
	}
	b, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	if len(b) > 0xFFFFFF {
		return errors.New("rtmp: AMF0 message too large")
	}

	c.writeChunkBasicHeader(0, 2)
	c.writeType0ChunkMessageHeader(0, uint32(len(b)), 20, 0, 2)
	c.bufw.Write(b)
	c.bufw.Flush()
	return nil
}

func (c *conn) writeAMF0NetConnectionConnectSuccess() error {
	msg := &amf.AMF0Msg{
		0: "_result",
		1: 1.0,
		2: amf.AMF0Object{},
		3: amf.AMF0Object{
			"level": "status",
			"code":  "NetConnection.Connect.Success",
		},
	}
	b, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	if len(b) > 0xFFFFFF {
		return errors.New("rtmp: AMF0 message too large")
	}

	c.writeChunkBasicHeader(0, 2)
	c.writeType0ChunkMessageHeader(0, uint32(len(b)), 20, 0, 2)
	c.bufw.Write(b)
	c.bufw.Flush()
	return nil
}
