package protocol

import (
	"math/big"
	"strings"
)

// ShiftedBigIntConfig configures decimal formatting for ShiftedBigInt and XL1Amount.
type ShiftedBigIntConfig struct {
	Places            int
	MaxDecimal        int
	MaxCharacters     int
	MinDecimals       int
	GroupingSeparator string
	DecimalSeparator  string
}

// DefaultShiftedBigIntConfig returns the standard en_US XL1 display configuration
// matching sdk-xyo-client-swift and sdk-xyo-client-android.
func DefaultShiftedBigIntConfig() ShiftedBigIntConfig {
	return ShiftedBigIntConfig{
		Places:            PlacesXL1,
		MaxDecimal:        PlacesXL1,
		MaxCharacters:     9,
		MinDecimals:       1,
		GroupingSeparator: ",",
		DecimalSeparator:  ".",
	}
}

// ShiftedBigInt formats arbitrary-precision integers with fixed decimal scaling using
// exact floor-truncated BigInt arithmetic (no floating-point precision loss).
type ShiftedBigInt struct {
	value  *big.Int
	config ShiftedBigIntConfig
}

// NewShiftedBigInt creates a ShiftedBigInt with value and config.
func NewShiftedBigInt(value *big.Int, cfg ShiftedBigIntConfig) ShiftedBigInt {
	if cfg.GroupingSeparator == "" {
		cfg.GroupingSeparator = ","
	}
	if cfg.DecimalSeparator == "" {
		cfg.DecimalSeparator = "."
	}
	return ShiftedBigInt{
		value:  safeBigInt(value),
		config: cfg,
	}
}

// ToFullString formats the value with all cfg.Places fractional digits (no grouping).
func (s ShiftedBigInt) ToFullString() string {
	places := s.config.Places
	if places <= 0 {
		return s.value.String()
	}
	negative := s.value.Sign() < 0
	abs := new(big.Int).Abs(s.value)
	divisor := AttoConvertFactor(places)
	intPart, rem := new(big.Int).QuoRem(abs, divisor, new(big.Int))

	frac := rem.String()
	if len(frac) < places {
		frac = strings.Repeat("0", places-len(frac)) + frac
	}
	prefix := ""
	if negative {
		prefix = "-"
	}
	return prefix + intPart.String() + s.config.DecimalSeparator + frac
}

// ToShortString formats the value with grouping separators and trimmed trailing fractional zeros
// down to MinDecimals, bounded by MaxDecimal and MaxCharacters.
func (s ShiftedBigInt) ToShortString() string {
	places := s.config.Places
	negative := s.value.Sign() < 0
	abs := new(big.Int).Abs(s.value)

	prefix := ""
	if negative {
		prefix = "-"
	}

	if places <= 0 {
		return prefix + groupDigits(abs.String(), s.config.GroupingSeparator)
	}

	divisor := AttoConvertFactor(places)
	intPart, rem := new(big.Int).QuoRem(abs, divisor, new(big.Int))
	intRaw := intPart.String()
	intGrouped := groupDigits(intRaw, s.config.GroupingSeparator)

	// Determine allowed decimal precision
	maxDec := s.config.MaxDecimal
	if maxDec > places {
		maxDec = places
	}
	if s.config.MaxCharacters > 0 {
		avail := s.config.MaxCharacters - len(intRaw) - 1
		if avail < s.config.MinDecimals {
			avail = s.config.MinDecimals
		}
		if avail < maxDec {
			maxDec = avail
		}
	}
	if maxDec <= 0 {
		return prefix + intGrouped
	}

	fracFull := rem.String()
	if len(fracFull) < places {
		fracFull = strings.Repeat("0", places-len(fracFull)) + fracFull
	}
	frac := fracFull[:maxDec]

	// Trim trailing zeros down to MinDecimals
	minDec := s.config.MinDecimals
	if minDec < 0 {
		minDec = 0
	}
	if minDec > len(frac) {
		minDec = len(frac)
	}
	frac = strings.TrimRight(frac, "0")
	if len(frac) < minDec {
		frac += strings.Repeat("0", minDec-len(frac))
	}
	if frac == "" {
		return prefix + intGrouped
	}
	return prefix + intGrouped + s.config.DecimalSeparator + frac
}

func groupDigits(digits, sep string) string {
	n := len(digits)
	if n <= 3 || sep == "" {
		return digits
	}
	var sb strings.Builder
	rem := n % 3
	if rem > 0 {
		sb.WriteString(digits[:rem])
		if rem < n {
			sb.WriteString(sep)
		}
	}
	for i := rem; i < n; i += 3 {
		if i > rem {
			sb.WriteString(sep)
		}
		sb.WriteString(digits[i : i+3])
	}
	return sb.String()
}

// XL1Amount wraps an AttoXL1 value with conversions to all 7 XL1 denominations and formatting helpers.
type XL1Amount struct {
	atto AttoXL1
}

// AmountFromAtto creates an XL1Amount from a *big.Int in AttoXL1, clamping to [0, maxAtto].
func AmountFromAtto(v *big.Int) XL1Amount {
	if v == nil || v.Sign() < 0 {
		return XL1Amount{atto: AttoXL1{v: big.NewInt(0)}}
	}
	maxVal := MaxValueForPlaces(PlacesAtto)
	if v.Cmp(maxVal) > 0 {
		return XL1Amount{atto: AttoXL1{v: maxVal}}
	}
	return XL1Amount{atto: AttoXL1{v: new(big.Int).Set(v)}}
}

// AmountFromAttoValue creates an XL1Amount from a validated AttoXL1.
func AmountFromAttoValue(a AttoXL1) XL1Amount {
	return XL1Amount{atto: a.ToAtto()}
}

// AmountFromPlaces constructs an XL1Amount from value scaled by 10^places (clamped to [0, maxAtto]).
func AmountFromPlaces(v *big.Int, places int) XL1Amount {
	if v == nil || v.Sign() < 0 {
		return AmountFromAtto(bigZero)
	}
	return AmountFromAtto(new(big.Int).Mul(v, AttoConvertFactor(places)))
}

func AmountFromFemto(v *big.Int) XL1Amount { return AmountFromPlaces(v, PlacesFemto) }
func AmountFromPico(v *big.Int) XL1Amount  { return AmountFromPlaces(v, PlacesPico) }
func AmountFromNano(v *big.Int) XL1Amount  { return AmountFromPlaces(v, PlacesNano) }
func AmountFromMicro(v *big.Int) XL1Amount { return AmountFromPlaces(v, PlacesMicro) }
func AmountFromMilli(v *big.Int) XL1Amount { return AmountFromPlaces(v, PlacesMilli) }
func AmountFromXL1(v *big.Int) XL1Amount   { return AmountFromPlaces(v, PlacesXL1) }

// Floor-division getters for all 7 denominations (matching JS/Swift/Android XL1Amount).

func (a XL1Amount) Atto() AttoXL1 { return a.atto.ToAtto() }

func (a XL1Amount) Femto() FemtoXL1 {
	return FemtoXL1{v: new(big.Int).Quo(a.atto.BigInt(), AttoConvertFactor(PlacesFemto))}
}

func (a XL1Amount) Pico() PicoXL1 {
	return PicoXL1{v: new(big.Int).Quo(a.atto.BigInt(), AttoConvertFactor(PlacesPico))}
}

func (a XL1Amount) Nano() NanoXL1 {
	return NanoXL1{v: new(big.Int).Quo(a.atto.BigInt(), AttoConvertFactor(PlacesNano))}
}

func (a XL1Amount) Micro() MicroXL1 {
	return MicroXL1{v: new(big.Int).Quo(a.atto.BigInt(), AttoConvertFactor(PlacesMicro))}
}

func (a XL1Amount) Milli() MilliXL1 {
	return MilliXL1{v: new(big.Int).Quo(a.atto.BigInt(), AttoConvertFactor(PlacesMilli))}
}

func (a XL1Amount) XL1() XL1 {
	return XL1{v: new(big.Int).Quo(a.atto.BigInt(), AttoConvertFactor(PlacesXL1))}
}

// ToFullString formats the amount in XL1 with all 18 fractional digits (or custom places).
func (a XL1Amount) ToFullString(places int) string {
	cfg := DefaultShiftedBigIntConfig()
	cfg.Places = places
	cfg.MaxDecimal = places
	return NewShiftedBigInt(a.atto.BigInt(), cfg).ToFullString()
}

// ToShortString formats the amount in XL1 with default short formatting (e.g. "1,234.0").
func (a XL1Amount) ToShortString() string {
	return NewShiftedBigInt(a.atto.BigInt(), DefaultShiftedBigIntConfig()).ToShortString()
}

// Format formats the amount using a custom ShiftedBigIntConfig.
func (a XL1Amount) Format(cfg ShiftedBigIntConfig) string {
	return NewShiftedBigInt(a.atto.BigInt(), cfg).ToShortString()
}
