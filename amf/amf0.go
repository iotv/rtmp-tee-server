package amf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

type AMF0Msg map[int]interface{}
type AMF0Object map[string]interface{}

// MarshalBinary allows AMF0Msg to adhere to the BinaryMarshaler interface.
// It serializes the existing AMF0Msg to the Network Order byte slice expected
// by AMF0 clients.
func (m *AMF0Msg) MarshalBinary() ([]byte, error) {
	ret := []byte{}
	mLen := len(*m)

	// Walk through keys
	for i := 0; i < mLen; i++ {
		if v, ok := (*m)[i]; !ok {
			return nil, fmt.Errorf("rtmp: AMF0: AMF messages must have contiguous key indexs. %d does not exist.", i)
		} else {
			switch v := v.(type) {
			case float64: // 0x00
				b := make([]byte, 8)
				binary.BigEndian.PutUint64(b, math.Float64bits(v))
				ret = append(ret, 0x00)
				ret = append(ret, b...)

			case bool: // 0x01
				var b byte
				if v {
					b = 0x01
				} else {
					b = 0x00
				}
				ret = append(ret, 0x01, b)

			case string: // 0x02
				if len(v) >= 0xFFFF { // Size is 2 bytes
					return nil, fmt.Errorf("rtmp: AMF0: string too long: length: %d, max: %d", len(v), 0xFFFF)
				}
				b := make([]byte, 2)
				binary.BigEndian.PutUint16(b, uint16(len(v)))

				ret = append(ret, 0x02)
				ret = append(ret, b...)
				ret = append(ret, []byte(v)...)

			case AMF0Object: // 0x03
				if b, err := v.MarshalBinary(); err == nil {
					ret = append(ret, b...)
				} else {
					return nil, err
				}

			case nil: // 0x05
				ret = append(ret, 0x05)

			default:
				return nil, fmt.Errorf("rtmp: AMF0: AMF type not recognized: %d: %v", i, v)
			}
		}
	}

	return ret, nil
}

// UnmarshalBinary allows AMFMsg to adhere to the BinaryUnmarshaler interface.
// It fills the fields of an existing AMF0Msg with values parsed from a
// byte slice, b.
func (m *AMF0Msg) UnmarshalBinary(b []byte) error {
	k := 0
	i := 0
	for i < len(b) {
		// First byte determines type
		switch b[i] {
		case 0x00: // number
			if (i + 9) > len(b) {
				return errors.New("rtmp: AMF0: number marker found without enough bytes for number.")
			}

			num := math.Float64frombits(binary.BigEndian.Uint64(b[i+1 : i+9]))
			(*m)[k] = num
			i = i + 9 // 1 + 8

		case 0x01: // boolean
			if (i + 1) > len(b) {
				return errors.New("rtmp: AMF0: boolean marker found without enough bytes for boolean.")
			}

			(*m)[k] = (b[i+1] != 0x00) // boolean. 0x00 = false. everything else is true
			i = i + 2                  // 1 + 1

		case 0x02: // string
			if (i + 2) > len(b) {
				return errors.New("rtmp: AMF0: string marker found without enough bytes for string size.")
			}

			strSz := binary.BigEndian.Uint16(b[i+1 : i+3])
			if (i + 2 + int(strSz)) > len(b) {
				return errors.New("rtmp: AMF0: string marker and size forund without enough bytes for string.")
			}
			str := string(b[i+3 : i+3+int(strSz)])
			(*m)[k] = str
			i = i + 3 + int(strSz) // 2 + 1

		case 0x03: // object
			if (i + 3) > len(b) {
				return errors.New("rtmp: AMF0: object marker found without enough bytes for object.")
			}

			objSz, err := scanForAMF0ObjectEnd(b[i:])
			if err != nil {
				return err
			}

			obj := &AMF0Object{}
			if err := obj.UnmarshalBinary(b[i : i+objSz]); err != nil {
				return err
			}
			(*m)[k] = *obj
			i = i + objSz

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

// MarshalBinary allows AMF0Object to adhere to the BinaryMarshaler interface.
// It serializes the existing AMF0Object to the Network Order byte slice expected
// by AMF0 clients. Typically this is function is called from an AMF0Msg
// having MarshalBinary called on it.
func (o *AMF0Object) MarshalBinary() ([]byte, error) {
	ret := []byte{}

	ret = append(ret, 0x03) // Object start marker 0x03
	for k, v := range *o {
		if len(k) >= 0xFFFF { // Size is 2 bytes
			return nil, fmt.Errorf("rtmp: AMF0: string too long: length: %d, max: %d", len(k), 0xFFFF)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(len(k)))
		ret = append(ret, b...)
		ret = append(ret, []byte(k)...)

		switch v := v.(type) {
		case float64: // 0x00
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, math.Float64bits(v))
			ret = append(ret, 0x00)
			ret = append(ret, b...)

		case bool: // 0x01
			var b byte
			if v {
				b = 0x01
			} else {
				b = 0x00
			}
			ret = append(ret, 0x01, b)

		case string: // 0x02
			if len(v) >= 0xFFFF { // Size is 2 bytes
				return nil, fmt.Errorf("rtmp: AMF0: string too long: length: %d, max: %d", len(v), 0xFFFF)
			}
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(len(v)))

			ret = append(ret, 0x02)
			ret = append(ret, b...)
			ret = append(ret, []byte(v)...)

		case AMF0Object: // 0x03
			if b, err := v.MarshalBinary(); err == nil {
				ret = append(ret, b...)
			} else {
				return nil, err
			}

		case nil: // 0x05
			ret = append(ret, 0x05)

		default:
			return nil, fmt.Errorf("rtmp: AMF0: AMF type not recognized: %s: %v", k, v)
		}
	}
	ret = append(ret, 0x00, 0x00, 0x09) // Null key marker 0x00 0x00; End Object marker 0x09

	return ret, nil
}

// UnmarshalBinary allows AMF0Object to the BinaryUnmarshaler interface.
// It fills the fields of an existing AMF0Object with values parsed from a
// byte slice, b.
func (o *AMF0Object) UnmarshalBinary(b []byte) error {
	i := 0

	// Ensure the first byte is the object start marker and skip it
	if len(b) < 1 || b[i] != 0x03 { // Object start marker
		return errors.New("rtmp: AMF0: Object binary must start with 0x03 object start marker.")
	}
	i += 1

	// Ensure the last 3 bytes are null key marker (0x00 0x00) and object end marker (0x09)
	if len(b) <= 3 || b[len(b)-3] != 0x00 || b[len(b)-2] != 0x00 || b[len(b)-1] != 0x09 {
		return errors.New("rtmp: AMF0: Object binary must end with 0x00 0x00 0x09 null key marker; object end marker.")
	}

	for i < (len(b) - 3) { // Exclude null key marker (0x00 0x00) and object end marker (0x09)
		if (i + 3) > len(b) {
			return errors.New("rtmp: AMF0: message object does not have enough bytes for key size.")
		}
		if kSz := binary.BigEndian.Uint16(b[i : i+2]); kSz != 0 {
			if (i + 2 + int(kSz)) > (len(b) - 3) {
				return errors.New("rtmp: AMF0: message object does not have enough bytes for key.")
			}
			k := string(b[i+2 : i+2+int(kSz)])
			i = i + 2 + int(kSz)
			if i > (len(b) - 3) {
				return errors.New("rtmp: AMF0: message object does not have enough bytes for key type.")
			}
			switch b[i] {
			case 0x00: // number
				if (i + 9) > (len(b) - 3) {
					return errors.New("rtmp: AMF0: number marker found without enough bytes for number.")
				}

				num := math.Float64frombits(binary.BigEndian.Uint64(b[i+1 : i+9]))
				(*o)[k] = num
				i = i + 9 // 1 + 8

			case 0x01: // boolean
				if (i + 1) > (len(b) - 3) {
					return errors.New("rtmp: AMF0: boolean marker found without enough bytes for boolean.")
				}

				(*o)[k] = (b[i+1] != 0x00) // boolean. 0x00 = false. everything else is true
				i = i + 2                  // 1 + 1

			case 0x02: // string
				if (i + 2) > (len(b) - 3) {
					return errors.New("rtmp: AMF0: string marker found without enough bytes for string size.")
				}

				strSz := binary.BigEndian.Uint16(b[i+1 : i+3])
				if (i + 2 + int(strSz)) > (len(b) - 3) {
					return errors.New("rtmp: AMF0: string marker and size forund without enough bytes for string.")
				}
				str := string(b[i+3 : i+3+int(strSz)])
				(*o)[k] = str
				i = i + 3 + int(strSz) // 1 + 2

			case 0x03: // object
				if (i + 3) > (len(b) - 3) {
					return errors.New("rtmp: AMF0: object marker found without enough bytes for object.")
				}

				objSz, err := scanForAMF0ObjectEnd(b[i:])
				if err != nil {
					return err
				}

				obj := &AMF0Object{}
				if err := obj.UnmarshalBinary(b[i : i+objSz]); err != nil {
					return err
				}
				(*o)[k] = obj
				i = i + objSz

			case 0x05: // null marker
				(*o)[k] = nil
				i = i + 1

			default:
				return fmt.Errorf("rtmp: AMF0: unimplemented marker found: %v.", b[i])
			}
		} else { // null key sigil
			i += 2 // TODO: ? I guess you can have a null key and continue the object?
		}
	}
	return nil
}

// scanForAMF0ObjectEnd is a recusrive scan for the end of the object.
// TODO: optimize this.
func scanForAMF0ObjectEnd(b []byte) (int, error) {
	i := 0

	// Ensure object start marker and skip it
	if len(b) < 1 || b[i] != 0x03 { // object start marker
		return 0, errors.New("rtmp: AMF0: object must start with object start marker 0x03.")
	}
	i += 1

	for i < len(b) {
		if (i + 3) > len(b) {
			return 0, errors.New("rtmp: AMF0: message object does not have enough bytes for key size.")
		}
		if kSz := binary.BigEndian.Uint16(b[i : i+2]); kSz != 0 {
			if (i + 2 + int(kSz)) > (len(b) - 3) {
				return 0, errors.New("rtmp: AMF0: message object does not have enough bytes for key.")
			}
			i = i + 2 + int(kSz)
			if i > (len(b) - 3) {
				return 0, errors.New("rtmp: AMF0: message object does not have enough bytes for key type.")
			}
			switch b[i] {
			case 0x00: // number
				if (i + 9) > (len(b) - 3) {
					return 0, errors.New("rtmp: AMF0: number marker found without enough bytes for number.")
				}
				i = i + 8 + 1

			case 0x01: // boolean
				if (i + 1) > (len(b) - 3) {
					return 0, errors.New("rtmp: AMF0: boolean marker found without enough bytes for boolean.")
				}
				i = i + 1 + 1

			case 0x02: // string
				if (i + 2) > (len(b) - 3) {
					return 0, errors.New("rtmp: AMF0: string marker found without enough bytes for string size.")
				}

				strSz := binary.BigEndian.Uint16(b[i+1 : i+3])
				if (i + 2 + int(strSz)) > (len(b) - 3) {
					return 0, errors.New("rtmp: AMF0: string marker and size forund without enough bytes for string.")
				}
				i = i + 2 + int(strSz) + 1

			case 0x03: // object
				if (i + 3) > (len(b) - 3) {
					return 0, errors.New("rtmp: AMF0: object marker found without enough bytes for object.")
				}

				offset, err := scanForAMF0ObjectEnd(b[i:])
				if err != nil {
					return 0, err
				}
				i = i + offset + 1

			case 0x05: // null marker
				i = i + 1

			default:
				return 0, fmt.Errorf("rtmp: AMF0: unimplemented marker found: %v.", b[i])
			}
		} else { // null key sigil
			i += 2
			if b[i] == 0x09 {
				i += 1
				return i, nil
			}
		}
	}
	return 0, errors.New("rtmp: AMF0: no object end found.")
}
