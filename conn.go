package rtmp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type chunk struct {
}

type conn struct {
	server *Server
	rwc    net.Conn

	// Input and output buffers on the connection
	bufr *bufio.Reader
	bufw *bufio.Writer

	// Stateful information about the previous incoming message
	prvIncMsgTime   *time.Time // Actual time it came in
	prvIncMsgTs     *uint32    // Timestamp on the message
	prvIncMsgTsD    *uint32    // Timestamp delta
	prvIncMsgLen    *uint32    // Message length
	prvIncMsgTypId  *uint8     // Message type ID
	prvIncMsgStrmId *uint32    // Message stream ID

	// Stateful information about the previous outgoing message
	prvOutgMsgTime   *time.Time // Actual time it went out
	prvOutgMsgTs     *uint32    // Timestamp on the message
	prvOutgMsgTsD    *uint32    // Timestamp delta
	prvOutgMsgLen    *uint32    // Message length
	prvOutgMsgTypId  *uint8     // Message type ID
	prvOutgMsgStrmId *uint32    // Message stream ID

	mu sync.Mutex
}

// handshake will perform the RTMP handshake to establish the connection.
// handshake is currently written in the context of a server listening to a
// client, however the handshake works both directions and this code should
// work for clients as well (where S0, S1, S2 are contextually C0, C1, C2)
// respectively.
// The RTMP handshake can be broken down as follows:
// S0 -> [version: 1 byte]       (only 3 is accepted at this time)
// S1 -> [timestamp: 4 bytes]    (epoch timestamp in milliseconds)
//       [zeroes: 4 bytes]       (zeroes for padding)
//       [random: 1528 bytes]    (random bytes)
// <- C0 [version: 1 byte]       (only 3 is accepeted at this time)
// <- C1 [timestamp: 4 bytes]    (epoch timestamp in milliseconds)
//       [zeroes: 4 bytes]       (zeroes for padding)
//       [random: 1528]          (random bytes)
// <Wait> The client and server packets must be in their own order, but their
//        order is idependent so S1 may arrive before C1 is sent or vice versa
// S2 -> [C1 timestamp: 4 bytes] (an echo of the timestamp sent in C1)
//       [timestamp: 4 bytes]    (the epoch timestamp C1 recieved at)
//       [C1 random: 1528 bytes] (an echo of the random sent in C1)
// <- C2 [S1 timestamp: 4 bytes] (an echo of the timestamp send in S1)
//       [timestamp: 4 bytes]    (the epoch timestamp S1 recieved at)
//       [S1 random: 1528 bytes] (an echo of the random sent in S1)
// <end> The order of S2 and C2 is also independent but must happen after the
// exchange of C1 and S1. Note that the behavior is reflected, so once the
// TCP dial and accept occurs, the handshake is the same for server and client
func (c *conn) handshake(ctx context.Context) error {
	// FIXME: set timeouts
	// FIXME: use pools for byte slices

	// S0, S1
	// Write s0
	if err := c.bufw.WriteByte(0x03); err != nil {
		return fmt.Errorf("rtmp: handshake S0 write failed: %s", err.Error())
	}
	// Write s0 timestamp
	s1Timestamp := make([]byte, 4)
	binary.BigEndian.PutUint32(s1Timestamp, getUint32MilsTimestamp())
	if s1TSLen, err := c.bufw.Write(s1Timestamp); s1TSLen != 4 || err != nil {
		return fmt.Errorf("rtmp: handshake S1 timestamp write failed: %s", err.Error())
	}
	// Write s1 zeroes
	if s1ZLen, err := c.bufw.Write([]byte{0, 0, 0, 0}); s1ZLen != 4 || err != nil {
		return fmt.Errorf("rtmp: handshake S1 zeroes write failed: %s", err.Error())
	}
	// Write s1 random bytes
	s1Random := make([]byte, 1528)
	if s1RandLen, err := rand.Read(s1Random); s1RandLen != 1528 || err != nil {
		return fmt.Errorf("rtmp: S1 random entropy error: %s", err.Error())
	}
	if s1RandLen, err := c.bufw.Write(s1Random); s1RandLen != 1528 || err != nil {
		return fmt.Errorf("rtmp: handshake S1 random write failed: %s", err.Error())
	}
	// Flush s0 and s1 to network
	if err := c.bufw.Flush(); err != nil {
		return fmt.Errorf("rtmp: handshake S0, S1 flush failed: %s", err.Error())
	}

	// CO, C1
	// Read c0
	if c0, err := c.bufr.ReadByte(); c0 != 0x03 || err != nil {
		return fmt.Errorf("rtmp: handshake C0 read version byte failed: %s", err.Error())
	}
	// Read and store c1
	c1 := make([]byte, 1536)
	if c1Len, err := c.bufr.Read(c1); c1Len != 1536 || err != nil {
		return fmt.Errorf("rtmp: handshake C1 read failed: %s", err.Error())
	}

	// TODO: figure out what to do with this.
	// OBS thinks this is incorrect. The RTMP spec says it's correct.
	// // S2
	// // Write s2 client timestamp
	// if s2CTSLen, err := c.bufw.Write(c1[:4]); s2CTSLen != 4 || err != nil {
	//   return fmt.Errorf("rtmp: handshake S2 client timestamp write failed: %s", err.Error())
	// }
	// // Write s2 server timestamp
	// s2STimestamp := make([]byte, 4)
	// binary.BigEndian.PutUint32(s2STimestamp, getUint32MilsTimestamp())
	// if s2STSLen, err := c.bufw.Write(s2STimestamp); s2STSLen != 4 || err != nil {
	//   return fmt.Errorf("rtmp: handshake S2 server timestamp write failed: %s", err.Error())
	// }
	// // Write s2 ack client random
	// if s2RandLen, err := c.bufw.Write(c1[8:]); s2RandLen != 1528 || err != nil {
	//   return fmt.Errorf("rtmp: handshake S2 acknowledge client random write failed: %s", err.Error())
	// }
	// FIXME: this is wrong. Obs likes it, but it's wrong.
	if s2, err := c.bufw.Write(c1); s2 != 1536 || err != nil {
		return fmt.Errorf("rtmp: handshake s2 write failed: %s", err.Error())
	}
	// Flush s2 to network
	if err := c.bufw.Flush(); err != nil {
		return fmt.Errorf("rtmp: handshake S2 flush failed: %s", err.Error())
	}

	// C2
	c2 := make([]byte, 1536)
	if c1Len, err := c.bufr.Read(c2); c1Len != 1536 || err != nil {
		return fmt.Errorf("rtmp: handshake C2 read failed: %s", err.Error())
	}

	// Verify C2 acknowledged S1 Random block
	if bytes.Compare(c2[8:], s1Random) != 0 {
		return fmt.Errorf("rtmp: handshake C2 did not acknowledge S2 random.")
	}

	// handshake success
	return nil
}

func (c *conn) receiveChunk(ctx context.Context) ([]byte, error) {
	// FIXME: set timeouts
	// FIXME: use pools for byte slices

	fmt.Println("-----")

	// Chunk Basic Header
	basicHeaderType, _ := c.bufr.Peek(1)
	fmt.Printf("basicHeaderFirstByte: %v\n", basicHeaderType)
	var basicHeaderLen int
	switch basicHeaderType[0] &^ 0xC0 { // Remove fmt
	case 0: // 2 byte streamId
		basicHeaderLen = 2
	case 1:
		basicHeaderLen = 3
	default:
		basicHeaderLen = 1
	}

	basicHeader := make([]byte, basicHeaderLen)
	bHPadding := make([]byte, 4-basicHeaderLen)

	// Read basic header for the chunk
	if bHLen, err := c.bufr.Read(basicHeader); bHLen != basicHeaderLen || err != nil {
		return nil, fmt.Errorf("rtmp: read chunk basic header failed: %s", err.Error())
	}
	chunkHeaderFormat := (basicHeader[0] & 0xC0) >> 6 // read fmt from first 2 bits and move them to LSBs
	basicHeader[0] = basicHeader[0] &^ 0xC0           // remove fmt from first 2 bits
	streamId := binary.BigEndian.Uint32(append(bHPadding, basicHeader...))
	switch basicHeaderLen {
	case 2, 3:
		streamId += 64 // 2 and 3 byte headers exclude IDs 2-63. It's ghetto. It's RTMP.
	}
	fmt.Printf("chunkHeaderFormat: %v\n", chunkHeaderFormat)
	fmt.Printf("streamId: %v\n", streamId)

	// Chunk Message header
	var err error
	switch chunkHeaderFormat {
	case 0:
		err = c.readType0MessageHeader()
	case 1:
		err = c.readType1MessageHeader()
	case 2:
		err = c.readType2MessageHeader()
	default: // implied type 3 header
		err = c.verifyType3MessageHeader()
	}
	if err != nil {
		return nil, fmt.Errorf("rtmp: receive chunk failed: %s.", err.Error())
	}

	// TODO: remove diagnostic messages
	fmt.Printf("timestamp: %v\n", *c.prvIncMsgTs)
	fmt.Printf("msgLen: %v\n", *c.prvIncMsgLen)
	fmt.Printf("msgTypeId: %v\n", *c.prvIncMsgTypId)
	fmt.Printf("msgStreamId: %v\n", *c.prvIncMsgStrmId)

	// FIXME: do not allocate memory based on a network peer's demands. set a limit and obey it
	message := make([]byte, *c.prvIncMsgLen)
	c.bufr.Read(message)
	fmt.Printf("message: %v\n", message)

	switch *c.prvIncMsgTypId {
	case 20: // AMF0 command message
		// write a user result amf0
		if amf0, err := readAMF0Message(message); err != nil {
			fmt.Printf("Error Reading AMF0 message: %s\n", err.Error())
		} else {
			fmt.Printf("amf0: %v\n", amf0)
		}
		c.writeAMF0NetConnectionConnectSuccess()
		fmt.Println("Wrote amf0 back")
	}

	return nil, fmt.Errorf("rtmp: recieve chunk not implemented")
}

func (c *conn) readType0MessageHeader() error {
	now := time.Now()

	header := make([]byte, 11)
	if hLen, err := c.bufr.Read(header); hLen != 11 || err != nil {
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
		return errors.New("rtmp: cannot read type 1 message header if no previous type 0 has been sent with stream id.")
	}
	if c.prvIncMsgTs == nil {
		return errors.New("rtmp: cannot read type 1 message header if no previous type 0, has been sent with message timestamp.")
	}

	now := time.Now()

	header := make([]byte, 7)
	if hLen, err := c.bufr.Read(header); hLen != 7 || err != nil {
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
		return errors.New("rtmp: cannot read type 2 message header if no previous type 0 has been sent with stream id.")
	}
	if c.prvIncMsgTs == nil {
		return errors.New("rtmp: cannot read type 2 message header if no previous type 0, has been sent with message timestamp.")
	}
	if c.prvIncMsgLen == nil {
		return errors.New("rtmp: cannot read type 2 message header if no previous type 0,1 has been sent with message length.")
	}
	if c.prvIncMsgTypId == nil {
		return errors.New("rtmp: cannot read type 2 message header if no previous type 0,1 has been sent with message type id.")
	}

	now := time.Now()

	header := make([]byte, 3)
	if hLen, err := c.bufr.Read(header); hLen != 3 || err != nil {
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
		return errors.New("rtmp: cannot read type 3 message header if no previous type 0 has been sent with stream id.")
	}
	if c.prvIncMsgTs == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 0, has been sent with message timestamp.")
	}
	if c.prvIncMsgLen == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 0,1 has been sent with message length.")
	}
	if c.prvIncMsgTypId == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 0,1 has been sent with message type id.")
	}
	if c.prvIncMsgTsD == nil {
		return errors.New("rtmp: cannot read type 3 message header if no previous type 1,2 has been sent with message timestamp delta.")
	}

	now := time.Now()

	msgTs := (*c.prvIncMsgTs + *c.prvIncMsgTsD) % 0x01000000 // keep it to 3 bytes by rolling it

	c.prvIncMsgTime = &now
	c.prvIncMsgTs = &msgTs

	return nil
}

// FIXME: parameterize variables
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
//    format => fmt (this is a libary used here)
//    chunkStreamId => cs id
func (c *conn) writeChunkBasicHeader(format uint8, chunkStreamId uint32) error {
	if format > 3 {
		return errors.New("rtmp: failed to write chunk basic header: format larger than 2 bits.")
	}
	if chunkStreamId > 65599 {
		return errors.New("rtmp: failed to write chunk basic header: chunk stream id greater than max.")
	} else if chunkStreamId < 2 {
		return errors.New("rtmp: failed to write chunk basic header: chunk stream id less than min.")
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
		return fmt.Errorf("rtmp: failed to write chunk basic header: invalid fmt: %d.", format)
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
		return fmt.Errorf("rtmp: failed to write chunk basic header: invalid id: %d.", chunkStreamId)
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
		return fmt.Errorf("rtmp: failed to write type 0 chunk message header: message length too large: %d.", msgLen)
	}

	// TODO: maybe DGAF about this?
	// Check if msgType is part of messages we know about
	switch msgType {
	case 1, 2, 3, 4, 5, 6:
		// RTMP Spec says message stream id must be 0 for stream control messages
		if msgStrmId != 0 {
			fmt.Errorf("rtmp: failed to write type 0 chunk message header: message stream id must be 0 but was: %d.", msgStrmId)
		}

		// RTMP Spec says chunk stream id must be 2 for stream control messages
		// FIXME: it's a little late to catch this error... might need to fix where
		// we check this or recover by finishing writing a blank message
		if chunkStreamId != 2 {
			fmt.Errorf("rtmp: failed to write type 0 chunk message header: chunk stream id must be 2 but was: %d.", chunkStreamId)
		}
	case 8, 9, 15, 16, 17, 18, 19, 20, 22:
		// we recognize this. ensure the chunk stream id isn't the control stream or weird
		// chunk stream id 0 and 1 are formatting reserved.
		// FIXME: it's a little late to catch this error... might need to fix where
		// we check this or recover by finishing writing a blank message
		if chunkStreamId < 2 {
			fmt.Errorf("rtmp: failed to write type 0 chunk message header: Invalid chunk stream id: %d.", chunkStreamId)
		} else if chunkStreamId == 2 { // 2 is reserved for types 1-6
			fmt.Errorf("rtmp: failed to write type 0 chunk message header: chunk stream id 2 is reserved for protocol control.")
		}
		// It all looks good. do nothing
	default:
		return fmt.Errorf("rtmp: failed to write type 0 chunk message header: msgType not recognized: %d.", msgType)
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

func (c *conn) writeAMF0NetConnectionConnectSuccess() error {
	c.writeChunkBasicHeader(0, 2)
	//c.writeType0ChunkMessageHeader(0, 81, 20, 0, 2)

	//c.bufw.Write([]byte{2})
	c.bufw.Write([]byte{0, 0, 0})    // empty timestamp
	c.bufw.Write([]byte{0, 0, 81})   // message length
	c.bufw.Write([]byte{20})         // AMF0 message!
	c.bufw.Write([]byte{0, 0, 0, 0}) // control msg stream id

	c.bufw.Write([]byte{2, 0, 7, 95, 114, 101, 115, 117, 108, 116})                           // string "_result"
	c.bufw.Write([]byte{0, 63, 240, 0, 0, 0, 0, 0, 0})                                        // number: 1.0 i guess?
	c.bufw.Write([]byte{3})                                                                   // object marker for properties
	c.bufw.Write([]byte{0, 0, 9})                                                             // object end marker for properties
	c.bufw.Write([]byte{3})                                                                   // object marker for information
	c.bufw.Write([]byte{0, 5, 108, 101, 118, 101, 108, 2, 0, 6, 115, 116, 97, 116, 117, 115}) // level: "status" k/v
	c.bufw.Write([]byte{
		0, 4, 99, 111, 100,
		101, 2, 0, 29, 78,
		101, 116, 67, 111,
		110, 110, 101, 99,
		116, 105, 111, 110,
		46, 67, 111, 110,
		110, 101, 99, 116,
		46, 83, 117, 99, 99,
		101, 115, 115}) // "code: "NetConnection.Connect.Success"
	c.bufw.Write([]byte{0, 0, 9}) // object end marker for information
	c.bufw.Flush()
	return nil
}

// serve will serve a connection with RTMP.
// It handles handshakes, control messages and dispatches RTMP server handlers
// based on incoming chunks. It also manages the lifecycle of the
// RTMP connection.
func (c *conn) serve(ctx context.Context) {
	c.bufr = bufio.NewReader(c.rwc) // TODO: add size here? // TODO: make a sync pool
	c.bufw = bufio.NewWriter(c.rwc) // TODO: add size here? // TODO: make a sync pool

	ctx, cancelCtx := context.WithCancel(ctx)
	defer cancelCtx()

	if c.handshake(ctx) != nil {
		c.rwc.Close()
	}
	//i := 0
	for {
		if _, err := c.receiveChunk(ctx); err != nil {
			//if i > 2 {
			//c.rwc.Close()
			//  break
			//}
			//i += 1
		}
	}
}
