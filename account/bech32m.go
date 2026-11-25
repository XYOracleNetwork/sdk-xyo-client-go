package account

import (
	"errors"
	"fmt"
	"strings"
)

const (
	bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	bech32mConst  = 0x2bc830a3
)

var bech32Generators = [5]uint32{
	0x3b6a57b2,
	0x26508e6d,
	0x1ea119fa,
	0x3d4233dd,
	0x2a1462b3,
}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 != 0 {
				chk ^= bech32Generators[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	ret := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		ret = append(ret, hrp[i]>>5)
	}
	ret = append(ret, 0)
	for i := 0; i < len(hrp); i++ {
		ret = append(ret, hrp[i]&31)
	}
	return ret
}

func bech32mCreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ bech32mConst
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return checksum
}

func bech32mVerifyChecksum(hrp string, data []byte) bool {
	values := append(bech32HRPExpand(hrp), data...)
	return bech32Polymod(values) == bech32mConst
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	maxv := uint32((1 << toBits) - 1)
	out := make([]byte, 0, (len(data)*int(fromBits)+int(toBits)-1)/int(toBits))

	for _, b := range data {
		if uint32(b)>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data range: %d", b)
		}
		acc = (acc << fromBits) | uint32(b)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("invalid bech32m padding")
	}
	return out, nil
}

// EncodeBech32m encodes raw bytes with the given human-readable part using BIP-350 Bech32m.
func EncodeBech32m(hrp string, payload []byte) (string, error) {
	if len(hrp) == 0 || len(hrp) > 83 {
		return "", fmt.Errorf("invalid HRP length: %d", len(hrp))
	}
	hrp = strings.ToLower(hrp)
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", fmt.Errorf("invalid HRP character at index %d", i)
		}
	}
	data5, err := convertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	combined := append(data5, bech32mCreateChecksum(hrp, data5)...)
	var sb strings.Builder
	sb.Grow(len(hrp) + 1 + len(combined))
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, b := range combined {
		sb.WriteByte(bech32Charset[b])
	}
	return sb.String(), nil
}

// DecodeBech32m decodes a Bech32m string, returning the HRP and raw payload bytes.
// Rejects mixed case strings per BIP-173/BIP-350.
func DecodeBech32m(encoded string) (string, []byte, error) {
	if len(encoded) < 8 || len(encoded) > 90 {
		return "", nil, fmt.Errorf("invalid bech32m length: %d", len(encoded))
	}
	hasLower := false
	hasUpper := false
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		if c < 33 || c > 126 {
			return "", nil, fmt.Errorf("invalid character at %d", i)
		}
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
	}
	if hasLower && hasUpper {
		return "", nil, errors.New("mixed case in bech32m string")
	}

	lower := strings.ToLower(encoded)
	sep := strings.LastIndexByte(lower, '1')
	if sep < 1 || sep+7 > len(lower) {
		return "", nil, errors.New("invalid bech32m separator position")
	}

	hrp := lower[:sep]
	dataPart := lower[sep+1:]
	data5 := make([]byte, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		idx := strings.IndexByte(bech32Charset, dataPart[i])
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid bech32m character %q", dataPart[i])
		}
		data5[i] = byte(idx)
	}
	if !bech32mVerifyChecksum(hrp, data5) {
		return "", nil, errors.New("invalid bech32m checksum")
	}
	payload, err := convertBits(data5[:len(data5)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, payload, nil
}
