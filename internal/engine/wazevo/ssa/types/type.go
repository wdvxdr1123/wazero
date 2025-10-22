package types

import "strings"

type Type struct {
	Kind     Kind
	bits     uint8
	elements []*Type
}

type Kind uint8

const (
	KindInvalid Kind = iota
	KindInteger
	KindFloat
	KindVector
	KindTuple
	KindFunc
	KindBlock // TODO: Remove this kind later
)

// basic types
var Invalid = &Type{Kind: KindInvalid}
var I32 = &Type{Kind: KindInteger, bits: 32}
var I64 = &Type{Kind: KindInteger, bits: 64}
var F32 = &Type{Kind: KindFloat, bits: 32}
var F64 = &Type{Kind: KindFloat, bits: 64}
var V128 = &Type{Kind: KindVector, bits: 128}

// high-level types
var Func = &Type{Kind: KindFunc}
var Block = &Type{Kind: KindBlock}

// IsInt returns true if the type is an integer type.
func (t Type) IsInt() bool {
	return t.Kind == KindInteger
}

// IsFloat returns true if the type is a floating point type.
func (t Type) IsFloat() bool {
	return t.Kind == KindFloat
}

// Bits returns the number of bits required to represent the type.
func (t Type) Bits() byte {
	switch t.Kind {
	case KindInteger, KindFloat:
		if t.bits != 32 && t.bits != 64 {
			panic("Integer and Float types must have either 32 or 64 bits")
		}
		return t.bits
	case KindVector:
		if t.bits != 128 {
			panic("Vector type must have 128 bits")
		}
		return t.bits
	default:
		panic("Bits() is only valid for Integer, Float, and Vector types")
	}
}

// Size returns the number of bytes required to represent the type.
func (t Type) Size() byte {
	return t.Bits() / 8
}

func (t Type) Invalid() bool {
	return t.Kind == KindInvalid
}

func (t Type) IsTuple() bool {
	return t.Kind == KindTuple
}

func (t Type) Len() int {
	if !t.IsTuple() {
		panic("Len() is only valid for tuple types")
	}
	return len(t.elements)
}

func (t Type) At(i int) *Type {
	if !t.IsTuple() {
		panic("At() is only valid for tuple types")
	}
	return t.elements[i]
}

func (t Type) String() string {
	switch t.Kind {
	case KindInvalid:
		return "invalid"
	case KindInteger:
		if t.bits == 32 {
			return "i32"
		}
		return "i64"
	case KindFloat:
		if t.bits == 32 {
			return "f32"
		}
		return "f64"
	case KindVector:
		return "v128"
	case KindTuple:
		sb := strings.Builder{}
		sb.WriteString("tuple{")
		for i, elem := range t.elements {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(elem.String())
		}
		sb.WriteString("}")
		return sb.String()
	}
	return "unknown"
}

func NewTuple(elements ...*Type) *Type {
	return &Type{
		Kind:     KindTuple,
		elements: elements,
	}
}
