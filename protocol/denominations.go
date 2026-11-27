package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// XL1Places defines the decimal places for each XL1 denomination relative to AttoXL1 (10^0).
const (
	PlacesAtto  = 0
	PlacesFemto = 3
	PlacesPico  = 6
	PlacesNano  = 9
	PlacesMicro = 12
	PlacesMilli = 15
	PlacesXL1   = 18

	// MaxAttoDigits is 32, so max AttoXL1 = 10^32 - 1 (matching @xyo-network/xl1-protocol-model).
	MaxAttoDigits = 32
)

var (
	bigZero = big.NewInt(0)
	bigTen  = big.NewInt(10)

	// ErrNegativeAmount is returned when constructing a denomination from a negative value.
	ErrNegativeAmount = errors.New("XL1 amount cannot be negative")
	// ErrAmountOverflow is returned when a denomination exceeds its maximum value 10^(32-places) - 1.
	ErrAmountOverflow = errors.New("XL1 amount exceeds maximum value")
)

// AttoConvertFactor returns 10^places as a new *big.Int.
func AttoConvertFactor(places int) *big.Int {
	if places <= 0 {
		return big.NewInt(1)
	}
	return new(big.Int).Exp(bigTen, big.NewInt(int64(places)), nil)
}

// MaxValueForPlaces returns 10^(32-places) - 1 as a new *big.Int.
func MaxValueForPlaces(places int) *big.Int {
	exp := MaxAttoDigits - places
	if exp < 0 {
		exp = 0
	}
	max := new(big.Int).Exp(bigTen, big.NewInt(int64(exp)), nil)
	return max.Sub(max, big.NewInt(1))
}

func validateDenomination(v *big.Int, places int) (*big.Int, error) {
	if v == nil {
		return big.NewInt(0), nil
	}
	if v.Sign() < 0 {
		return nil, ErrNegativeAmount
	}
	if v.Cmp(MaxValueForPlaces(places)) > 0 {
		return nil, fmt.Errorf("%w (places=%d)", ErrAmountOverflow, places)
	}
	return new(big.Int).Set(v), nil
}

func parseBigIntString(s string) (*big.Int, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, errors.New("empty numeric string")
	}
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		hexPart := trimmed[2:]
		if hexPart == "" {
			return nil, fmt.Errorf("empty hex integer: %q", s)
		}
		v, ok := new(big.Int).SetString(hexPart, 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex integer: %q", s)
		}
		return v, nil
	}
	v, ok := new(big.Int).SetString(trimmed, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal integer: %q", s)
	}
	return v, nil
}

// AttoXL1 represents the base XL1 denomination (10^0 atto = 10^-18 XL1).
type AttoXL1 struct{ v *big.Int }

// FemtoXL1 represents 10^3 AttoXL1.
type FemtoXL1 struct{ v *big.Int }

// PicoXL1 represents 10^6 AttoXL1.
type PicoXL1 struct{ v *big.Int }

// NanoXL1 represents 10^9 AttoXL1.
type NanoXL1 struct{ v *big.Int }

// MicroXL1 represents 10^12 AttoXL1.
type MicroXL1 struct{ v *big.Int }

// MilliXL1 represents 10^15 AttoXL1.
type MilliXL1 struct{ v *big.Int }

// XL1 represents 10^18 AttoXL1.
type XL1 struct{ v *big.Int }

func NewAttoXL1(v *big.Int) (AttoXL1, error) {
	norm, err := validateDenomination(v, PlacesAtto)
	if err != nil {
		return AttoXL1{}, err
	}
	return AttoXL1{v: norm}, nil
}

func NewAttoXL1Int64(v int64) (AttoXL1, error) {
	return NewAttoXL1(big.NewInt(v))
}

// AttoXL1FromString parses a decimal string (or 0x-prefixed hex string) into an AttoXL1.
func AttoXL1FromString(s string) (AttoXL1, error) {
	v, err := parseBigIntString(s)
	if err != nil {
		return AttoXL1{}, err
	}
	return NewAttoXL1(v)
}

// AttoXL1FromHex strictly parses a hexadecimal string (bare hex or 0x-prefixed) into an AttoXL1.
func AttoXL1FromHex(hexStr string) (AttoXL1, error) {
	clean := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(hexStr), "0x"), "0X")
	if clean == "" {
		return AttoXL1{}, errors.New("empty hex AttoXL1")
	}
	v, ok := new(big.Int).SetString(clean, 16)
	if !ok {
		return AttoXL1{}, fmt.Errorf("invalid hex AttoXL1: %q", hexStr)
	}
	return NewAttoXL1(v)
}

// MarshalJSON encodes AttoXL1 as a base-10 JSON string to preserve full arbitrary precision.
func (a AttoXL1) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON decodes AttoXL1 from a JSON decimal/0x-hex string or JSON integer number.
func (a *AttoXL1) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		a.v = big.NewInt(0)
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		parsed, err := AttoXL1FromString(s)
		if err != nil {
			return err
		}
		*a = parsed
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil {
		return fmt.Errorf("unmarshal AttoXL1: %w", err)
	}
	parsed, err := AttoXL1FromString(n.String())
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

func (a AttoXL1) BigInt() *big.Int {
	if a.v == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(a.v)
}

func (a AttoXL1) ToAtto() AttoXL1   { return AttoXL1{v: a.BigInt()} }
func (a AttoXL1) String() string    { return a.BigInt().String() }
func (a AttoXL1) Hex() string       { return "0x" + a.BigInt().Text(16) }
func (a AttoXL1) BareHex() string   { return a.BigInt().Text(16) }
func (a AttoXL1) Cmp(b AttoXL1) int { return a.BigInt().Cmp(b.BigInt()) }
func (a AttoXL1) Add(b AttoXL1) (AttoXL1, error) {
	return NewAttoXL1(new(big.Int).Add(a.BigInt(), b.BigInt()))
}
func (a AttoXL1) Sub(b AttoXL1) (AttoXL1, error) {
	return NewAttoXL1(new(big.Int).Sub(a.BigInt(), b.BigInt()))
}

func NewFemtoXL1(v *big.Int) (FemtoXL1, error) {
	norm, err := validateDenomination(v, PlacesFemto)
	return FemtoXL1{v: norm}, err
}
func (d FemtoXL1) BigInt() *big.Int { return safeBigInt(d.v) }
func (d FemtoXL1) String() string   { return d.BigInt().String() }
func (d FemtoXL1) ToAtto() AttoXL1 {
	return AttoXL1{v: new(big.Int).Mul(d.BigInt(), AttoConvertFactor(PlacesFemto))}
}

func NewPicoXL1(v *big.Int) (PicoXL1, error) {
	norm, err := validateDenomination(v, PlacesPico)
	return PicoXL1{v: norm}, err
}
func (d PicoXL1) BigInt() *big.Int { return safeBigInt(d.v) }
func (d PicoXL1) String() string   { return d.BigInt().String() }
func (d PicoXL1) ToAtto() AttoXL1 {
	return AttoXL1{v: new(big.Int).Mul(d.BigInt(), AttoConvertFactor(PlacesPico))}
}

func NewNanoXL1(v *big.Int) (NanoXL1, error) {
	norm, err := validateDenomination(v, PlacesNano)
	return NanoXL1{v: norm}, err
}
func (d NanoXL1) BigInt() *big.Int { return safeBigInt(d.v) }
func (d NanoXL1) String() string   { return d.BigInt().String() }
func (d NanoXL1) ToAtto() AttoXL1 {
	return AttoXL1{v: new(big.Int).Mul(d.BigInt(), AttoConvertFactor(PlacesNano))}
}

func NewMicroXL1(v *big.Int) (MicroXL1, error) {
	norm, err := validateDenomination(v, PlacesMicro)
	return MicroXL1{v: norm}, err
}
func (d MicroXL1) BigInt() *big.Int { return safeBigInt(d.v) }
func (d MicroXL1) String() string   { return d.BigInt().String() }
func (d MicroXL1) ToAtto() AttoXL1 {
	return AttoXL1{v: new(big.Int).Mul(d.BigInt(), AttoConvertFactor(PlacesMicro))}
}

func NewMilliXL1(v *big.Int) (MilliXL1, error) {
	norm, err := validateDenomination(v, PlacesMilli)
	return MilliXL1{v: norm}, err
}
func (d MilliXL1) BigInt() *big.Int { return safeBigInt(d.v) }
func (d MilliXL1) String() string   { return d.BigInt().String() }
func (d MilliXL1) ToAtto() AttoXL1 {
	return AttoXL1{v: new(big.Int).Mul(d.BigInt(), AttoConvertFactor(PlacesMilli))}
}

func NewXL1(v *big.Int) (XL1, error) {
	norm, err := validateDenomination(v, PlacesXL1)
	return XL1{v: norm}, err
}
func (d XL1) BigInt() *big.Int { return safeBigInt(d.v) }
func (d XL1) String() string   { return d.BigInt().String() }
func (d XL1) ToAtto() AttoXL1 {
	return AttoXL1{v: new(big.Int).Mul(d.BigInt(), AttoConvertFactor(PlacesXL1))}
}

func safeBigInt(v *big.Int) *big.Int {
	if v == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(v)
}
