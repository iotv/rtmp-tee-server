package rtmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type AMF0Msg map[int]interface{}
type AMF0Object map[string]interface{}

func (m *AMF0Msg) MarshalBinary() ([]byte, error) {
	ret := []byte{}
	mLen := len(*m)

	// Walk through keys
	for i := 0; i < mLen; i++ {
		if v, ok := (*m)[i]; ok {
			return nil, fmt.Errorf("rtmp: AMF0: AMF messages must have contiguous key indexs. %d does not exist.", i)
		} else {
			switch v := v.(type) {
			case float64:
				// 0x00
			case bool:
				// 0x01
			case string:
				// 0x02
			case AMF0Object:
				// 0x03
			case nil:
				// 0x05
			default:
				return nil, fmt.Errorf("rtmp: AMF0: AMF type not recognized: %d: %v", i, v)
			}
		}
	}

	return ret, nil
}

// UnmarshalBinary allows AMFMsg to adhere to the BinaryUnmarshaler interface.
// It converts a byte stream into the fields of an AMF0MSg
func (m *AMF0Msg) UnmarshalBinary(b []byte) error {
	msgLen := len(b)
	k := 0
	i := 0
	for i < msgLen {

		// First byte determines type
		switch b[i] {
		case 0x00: // number
			if (i + 9) > msgLen {
				return errors.New("rtmp: AMF0: number marker found without enough bytes for number.")
			}

			if num, err := readAMF0Number(b[i+1 : i+9]); err != nil {
				return err
			} else {
				(*m)[k] = *num
				i = i + 8 + 1
			}

		case 0x01: // boolean
			if (i + 1) > msgLen {
				return errors.New("rtmp: AMF0: boolean marker found without enough bytes for boolean.")
			}

			(*m)[k] = (b[i+1] != 0x00) // boolean. 0x00 = false. everything else is true
			i = i + 1 + 1

		case 0x02: // string
			if (i + 2) > msgLen {
				return errors.New("rtmp: AMF0: string marker found without enough bytes for string size.")
			}

			strSz := binary.BigEndian.Uint16(b[i+1 : i+3])
			if (i + 2 + int(strSz)) > msgLen {
				return errors.New("rtmp: AMF0: string marker and size forund without enough bytes for string.")
			}
			str := string(b[i+3 : i+3+int(strSz)])
			(*m)[k] = str
			i = i + 2 + int(strSz) + 1

		case 0x03: // object
			if (i + 3) > msgLen {
				return errors.New("rtmp: AMF0: object marker found without enough bytes for object.")
			}

			read, obj, err := readAMF0Object(b[i+1:]) // don't pass the object marker
			if err != nil {
				return err
			}
			(*m)[k] = obj
			i = i + read + 1

		case 0x05: // null marker
			(*m)[k] = nil
			i = i + 1

		default:
			return fmt.Errorf("rtmp: AMF0: unimplemented marker found: %v.", b[i])
		}

		k += 1
	}

	return nil
}

func (o *AMF0Object) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (o *AMF0Object) UnmarshalBinary(b []byte) error {
	return nil
}

func readAMF0Message(msg []byte) (AMF0Msg, error) {
	msgLen := len(msg)
	k := 0
	i := 0
	ret := AMF0Msg{}
	for i < msgLen {
		switch msg[i] {
		case 0x00: // number
			if (i + 8) > msgLen {
				return nil, errors.New("rtmp: AMF0: number marker found without enough bytes for number.")
			}
			num, err := readAMF0Number(msg[i+1 : i+9])
			if err != nil {
				return nil, err
			}
			ret[k] = *num
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
			if (i + 3) > msgLen {
				return nil, errors.New("rtmp: AMF0: object marker found without enough bytes for object.")
			}
			read, obj, err := readAMF0Object(msg[i+1:]) // don't pass the object marker
			if err != nil {
				return nil, err
			}
			ret[k] = obj
			i = i + read + 1
		case 0x05: // null marker
			ret[k] = nil
			i = i + 1
		default:
			return nil, fmt.Errorf("rtmp: AMF0: unimplemented marker found: %v.", msg[i])
		}
		k += 1
	}

	return ret, nil
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
	msgLen := len(b)
	i := 0
	ret := AMF0Object{}
	for i < msgLen {
		if (i + 3) > msgLen {
			return 0, nil, errors.New("rtmp: AMF0: message object does not have enough bytes for key size.")
		}
		if kSz := binary.BigEndian.Uint16(b[i : i+2]); kSz != 0 {
			if (i + 2 + int(kSz)) > msgLen {
				return i, nil, errors.New("rtmp: AMF0: message object does not have enough bytes for key.")
			}
			k := string(b[i+2 : i+2+int(kSz)])
			i = i + 2 + int(kSz)
			if i > msgLen {
				return 0, nil, errors.New("rtmp: AMF0: message object does not have enough bytes for key type.")
			}
			switch b[i] {
			case 0x00: // number
				if (i + 8) > msgLen {
					return i, nil, errors.New("rtmp: AMF0: number marker found without enough bytes for number.")
				}
				num, err := readAMF0Number(b[i+1 : i+9])
				if err != nil {
					return i, nil, err
				}
				ret[k] = *num
				i = i + 8 + 1
			case 0x01: // bool
				if (i + 1) > msgLen {
					return i, nil, errors.New("rtmp: AMF0: boolean marker found without enough bytes for boolean.")
				}
				ret[k] = (b[i+1] != 0x00) // boolean. 0x00 = false. everything else is true
				i = i + 1 + 1
			case 0x02: // string
				if (i + 2) > msgLen {
					return i, nil, errors.New("rtmp: AMF0: string marker found without enough bytes for string size.")
				}
				strSz := binary.BigEndian.Uint16(b[i+1 : i+3])
				if (i + 2 + int(strSz)) > msgLen {
					return i, nil, errors.New("rtmp: AMF0: string marker and size forund without enough bytes for string.")
				}
				str := string(b[i+3 : i+3+int(strSz)])
				ret[k] = str
				i = i + 2 + int(strSz) + 1
			case 0x03: // object
				if (i + 3) > msgLen {
					return i, nil, errors.New("rtmp: AMF0: object marker found without enough bytes for object.")
				}
				read, obj, err := readAMF0Object(b[i+1:]) // don't pass the object marker
				if err != nil {
					return i, nil, err
				}
				ret[k] = obj
				i = i + read + 1
			case 0x05: // null marker
				ret[k] = nil
				i = i + 1
			default:
				return i, nil, fmt.Errorf("rtmp: AMF0: unimplemented obj marker found: %v", b[i])
			}
		} else { // null key sigil
			if b[i+2] == 0x09 { // object end sigil
				i += 3
				return i, ret, nil
			}
			i += 2 // TODO: ? I guess you can have a null key and continue the object?
		}
	}
	return i, ret, nil
}
