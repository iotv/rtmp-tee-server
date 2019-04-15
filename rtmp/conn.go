package rtmp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
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

	// Stateful information about bytes recieved since acknowledgement
	sequenceNum   uint32
	ackWindowSize uint32

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
// <- C0 [version: 1 byte]       (only 3 is accepted at this time)
// <- C1 [timestamp: 4 bytes]    (epoch timestamp in milliseconds)
//       [zeroes: 4 bytes]       (zeroes for padding)
//       [random: 1528]          (random bytes)
// <Wait> The client and server packets must be in their own order, but their
//        order is independent so S1 may arrive before C1 is sent or vice versa
// S2 -> [C1 timestamp: 4 bytes] (an echo of the timestamp sent in C1)
//       [timestamp: 4 bytes]    (the epoch timestamp C1 received at)
//       [C1 random: 1528 bytes] (an echo of the random sent in C1)
// <- C2 [S1 timestamp: 4 bytes] (an echo of the timestamp send in S1)
//       [timestamp: 4 bytes]    (the epoch timestamp S1 received at)
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
		return fmt.Errorf("rtmp: handshake C2 did not acknowledge S2 random")
	}

	// handshake success
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
			c.rwc.Close()
			break
			//}
			//i += 1
		}
	}
}
