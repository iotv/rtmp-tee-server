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

type conn struct {
	server *Server
	rwc    net.Conn

  bufr *bufio.Reader
  bufw *bufio.Writer

  mu sync.Mutex
}


func (c *conn) handshake() error {
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

  // S2
  // Write s2 client timestamp
  if s2CTSLen, err := c.bufw.Write(c1[:4]); s2CTSLen != 4 || err != nil {
    return fmt.Errorf("rtmp: handshake S2 client timestamp write failed: %s", err.Error())
  }
  // Write s2 server timestamp
  s2STimestamp := make([]byte, 4)
  binary.BigEndian.PutUint32(s2STimestamp, getUint32MilsTimestamp())
  if s2STSLen, err := c.bufw.Write(s2STimestamp); s2STSLen != 4 || err != nil {
    return fmt.Errorf("rtmp: handshake S2 server timestamp write failed: %s", err.Error())
  }
  // Write s2 ack client random
  if s2RandLen, err := c.bufw.Write(c1[8:]); s2RandLen != 1528 || err != nil {
    return fmt.Errorf("rtmp: handshake S2 acknowledge client random write failed: %s", err.Error())
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

func (c *conn) serve(ctx context.Context) {
    c.bufr = bufio.NewReader(c.rwc) // TODO: add size here? // TODO: make a sync pool
    c.bufw = bufio.NewWriter(c.rwc) // TODO: add size here? // TODO: make a sync pool
    c.handshake()
    for {

    }
}
