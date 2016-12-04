package rtmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type AMF0Msg map[int]interface{}
type AMF0Object map[string]interface{}


func readAMF0Message(msg []byte) (AMF0Msg, error) {
	msgLen := len(msg)
	k := 0
	i := 0
	ret := AMF0Msg{}
	for i > msgLen {
		switch msg[i] {
		case 0x00: // number
			if (i + 8) > msgLen {
				return nil, errors.New("rtmp: AMF0: number marker found without enough bytes for number.")
			}
			num, err := readAMF0Number(msg[i+1 : i+8])
			if err != nil {
				return nil, err
			}
			ret[k] = num
			i = i + 8 + 1
		case 0x01: // boolean
			if (i + 1) > msgLen {
				return nil, errors.New("rtmp: AMF0: boolean marker found without enough bytes for boolean.")
			}
			ret[k] = (msg[i+1] != 0x00) // boolean. 0x00 = false. everything else is true
			i = i + 1 + 1
		case 0x02: // string
			if (i + 2) > msgLen {
				return nil, errors.New("rtmp: AMF0: string marker found without enough bytes for string size.")
			}
			strSz := binary.BigEndian.Uint16(msg[i+1 : i+3])
			if (i + 2 + int(strSz)) > msgLen {
				return nil, errors.New("rtmp: AMF0: string marker and size forund without enough bytes for string.")
			}
			str := string(msg[i+3 : i+3+int(strSz)])
			ret[k] = str
			i = i + 2 + int(strSz) + 1
		case 0x03: // object
		}
		k += 1
	}

	return nil, nil
}

func readAMF0Number(b []byte) (*float64, error) {
	var ret float64
	r := bytes.NewReader(b)
	if err := binary.Read(r, binary.BigEndian, &ret); err != nil {
		return nil, fmt.Errorf("rtmp: AMF0: failed to read number: %s", err.Error())
	}
	return &ret, nil
}

func readAMF0Object(b []byte) (int, AMF0Object, error) {
  
}
