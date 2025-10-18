package types

type Type uint8

const (
	Invalid Type = iota
	I32
	I64
	F32
	F64
	V128
	End
)

// IsInt returns true if the type is an integer type.
func (t Type) IsInt() bool {
	return t == I32 || t == I64
}

// IsFloat returns true if the type is a floating point type.
func (t Type) IsFloat() bool {
	return t == F32 || t == F64
}

// Bits returns the number of bits required to represent the type.
func (t Type) Bits() byte {
	switch t {
	case I32, F32:
		return 32
	case I64, F64:
		return 64
	case V128:
		return 128
	default:
		panic(int(t))
	}
}

// Size returns the number of bytes required to represent the type.
func (t Type) Size() byte {
	return t.Bits() / 8
}

func (t Type) Invalid() bool {
	return t == Invalid
}

func (t Type) String() string {
	switch t {
	case Invalid:
		return "invalid"
	case I32:
		return "i32"
	case I64:
		return "i64"
	case F32:
		return "f32"
	case F64:
		return "f64"
	case V128:
		return "v128"
	}
	return "unknown"
}
