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
)

type chunk struct {

}

type conn struct {
	server *Server
	rwc    net.Conn

  bufr *bufio.Reader
  bufw *bufio.Writer

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
  if s1ZLen, err := c.bufw.Write([]byte{0,0,0,0}); s1ZLen != 4 || err != nil {
    return fmt.Errorf("rtmp: handshake S1 zeroes write failed: %s", err.Error())
  }
  // Write s1 random bytes
  s1Random := make([]byte, 1528)
  if s1RandLen, err := rand.Read(s1Random); s1RandLen != 1528 || err != nil {
    return fmt.Errorf("rtmp: S1 random entropy error: %s", err.Error())
  }
  if s1RandLen, err:= c.bufw.Write(s1Random); s1RandLen != 1528 || err != nil {
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
  if s2, err := c.bufw.Write(c1); s2 != 1536 || err!= nil {
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

  // Chunk Basic Header
  basicHeaderType, _ := c.bufr.Peek(1)
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
  bHPadding := make([]byte, 4 - basicHeaderLen)

  // Read basic header for the chunk
  if bHLen, err := c.bufr.Read(basicHeader); bHLen != basicHeaderLen || err != nil {
    return nil, fmt.Errorf("rtmp: read chunk basic header failed: %s", err.Error())
  }
  chunkHeaderFormat := (basicHeader[0] & 0xC0) >> 6// read fmt from first 2 bits and move them to LSBs
  basicHeader[0] = basicHeader[0] &^ 0xC0 // remove fmt from first 2 bits
  streamId := binary.BigEndian.Uint32(append(bHPadding, basicHeader...))
  switch basicHeaderLen {
  case 2, 3:
    streamId += 64 // 2 and 3 byte headers exclude IDs 2-63. It's ghetto. It's RTMP.
  }
  fmt.Printf("basicHeaderType: %v\n", basicHeaderType)
  fmt.Printf("chunkHeaderFormat: %v\n", chunkHeaderFormat)
  fmt.Printf("streamId: %v\n", streamId)


  // Chunk Message header
  switch chunkHeaderFormat {
  case 0:
    // Type 0 Chunk Headers are 11 bytes long
    timestamp := make([]byte, 3)
    msgLen := make([]byte, 3)
    msgTypeId := make([]byte, 1)
    msgStreamId := make([]byte, 4)
    c.bufr.Read(timestamp)
    c.bufr.Read(msgLen)
    c.bufr.Read(msgTypeId)
    c.bufr.Read(msgStreamId)

    // FIXME: do not allocate memory based on what a network peer says, have a limit set on server
    message := make([]byte, binary.BigEndian.Uint32(append([]byte{0}, msgLen...)))
    c.bufr.Read(message)

    fmt.Printf("timestamp: %v\n", timestamp)
    fmt.Printf("msgLen: %v\n", msgLen)
    fmt.Printf("msgTypeId: %v\n", msgTypeId)
    fmt.Printf("msgStreamId: %v\n", msgStreamId)

    // LOUD
    fmt.Printf("message: %v\n", message)

    switch msgTypeId[0] {
    case 20: // AMF0 command message
      // // write a window size acknowledgement chunk
      // c.bufw.Write([]byte{2}) // Chunk basic header indicating low level control
      // // type 0 chunk response
      // c.bufw.Write([]byte{0, 0, 0}) // empty timestamp
      // c.bufw.Write([]byte{0, 0, 4}) // message length 4
      // c.bufw.Write([]byte{5}) //set messagetype id = 5; window ack size
      // c.bufw.Write([]byte{0, 0, 0, 0}) // control message stream id = 0
      // c.bufw.Write([]byte{0, 0, 250, 0})
      // c.bufw.Flush()
      //
      // // set bandwidth
      // c.bufw.Write([]byte{2}) // Chunk basic header for low level control
      // c.bufw.Write([]byte{0, 0, 0}) // empty timestamp
      // c.bufw.Write([]byte{0, 0, 5}) // message length 4
      // c.bufw.Write([]byte{6}) // msg type id = 6; set peer bw
      // c.bufw.Write([]byte{0, 0, 0, 0}) // control message stream id = 0
      // c.bufw.Write([]byte{0, 5, 0, 0, 0})
      // c.bufw.Flush()
      //
      // // write this terrible rtmp start stream thing
      // c.bufw.Write([]byte{2})
      // c.bufw.Write([]byte{0, 0, 0})
      // c.bufw.Write([]byte{0, 0, 17}) //message length
      // c.bufw.Write([]byte{4}) // user control message
      // c.bufw.Write([]byte{0, 0, 0, 0}) // control message stream id = 0
      // c.bufw.Write([]byte{4}) // rtmp message type???
      // c.bufw.Write([]byte{0, 0, 6}) // payload length
      // whocares := make([]byte, 4)
      // binary.BigEndian.PutUint32(whocares, getUint32MilsTimestamp())
      // c.bufw.Write(whocares)
      // c.bufw.Write([]byte{0, 0, 0}) // stream id 0?
      // c.bufw.Write([]byte{0, 0, 0, 0, 0, 0}) // ?? Stream begin. Stream 0?
      // c.bufw.Flush()

      // write a user result amf0
      c.bufw.Write([]byte{2}) // chunk id
      c.bufw.Write([]byte{0, 0, 0}) // empty timestamp
      c.bufw.Write([]byte{0, 0, 81}) // message length
      c.bufw.Write([]byte{20}) // AMF0 message!
      c.bufw.Write([]byte{0, 0, 0, 0}) // control msg stream id
      c.bufw.Write([]byte{2, 0, 7, 95, 114, 101, 115, 117, 108, 116}) // string "_result"
      c.bufw.Write([]byte{0, 63, 240, 0, 0, 0, 0, 0, 0}) // number: 1.0 i guess?
      c.bufw.Write([]byte{3}) // object marker for properties
      c.bufw.Write([]byte{0, 0, 9}) // object end marker for properties
      c.bufw.Write([]byte{3}) // object marker for information
      c.bufw.Write([]byte{0, 5, 108, 101, 118, 101, 108, 2, 0, 6, 115, 116, 97, 116, 117, 115 }) // level: "status" k/v
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
      fmt.Println("Wrote amf0 back")
    }
  case 1:
    timestampDelta := make([]byte, 3)
    msgLen := make([]byte, 3)
    msgTypeId := make([]byte, 3)
    c.bufr.Read(timestampDelta)
    c.bufr.Read(msgLen)
    c.bufr.Read(msgTypeId)

    // FIXME: do not allocate memory based on what a network peer says, have a limit set on server
    message := make([]byte, binary.BigEndian.Uint32(append([]byte{0}, msgLen...)))
    c.bufr.Read(message)

    fmt.Printf("timestamp: %v\n", timestampDelta)
    fmt.Printf("msgLen: %v\n", msgLen)
    fmt.Printf("msgTypeId: %v\n", msgTypeId)
    fmt.Printf("message: %v\n", message)
  case 2:
    timestampDelta := make([]byte, 3)
    fmt.Printf("timestamp: %v\n", timestampDelta)
  default: // should only be 3, as this is masked from 2 bits so 0-3 is exhaustive
    fmt.Println("nothing to see here.")
  }

  return nil, fmt.Errorf("rtmp: recieve chunk not implemented")
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
    i := 0
    for {
      if _, err := c.receiveChunk(ctx); err != nil {
        if i > 2 {
          c.rwc.Close()
          break
        }
        i += 1
      }
    }
}
