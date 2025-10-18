package ssa

import (
	"fmt"
	"math"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
)

// Variable is a unique identifier for a source program's variable and will correspond to
// multiple ssa Value(s).
//
// For example, `Local 1` is a Variable in WebAssembly, and Value(s) will be created for it
// whenever it executes `local.set 1`.
//
// Variable is useful to track the SSA Values of a variable in the source program, and
// can be used to find the corresponding latest SSA Value via Builder.FindValue.
//
// Higher 4-bit is used to store Type for this variable.
type Variable struct {
	id  uint32
	typ *types.Type
}

// String implements fmt.Stringer.
func (v Variable) String() string {
	return fmt.Sprintf("var%d", v.id)
}

func (v Variable) setType(typ *types.Type) Variable {
	v.typ = typ
	return v
}

func (v Variable) getType() *types.Type {
	return v.typ
}

// Value represents an SSA value with a type information. The relationship with Variable is 1: N (including 0),
// that means there might be multiple Variable(s) for a Value.
//
// 32 to 59-bit is used to store the unique identifier of the Instruction that generates this value if any.
// 60 to 63-bit is used to store Type for this value.
type Value struct {
	id     ValueID
	instID int32
	typ    *types.Type
}

// ValueID is the lower 32bit of Value, which is the pure identifier of Value without type info.
type ValueID uint32

const valueIDInvalid ValueID = math.MaxUint32

var ValueInvalid = Value{id: valueIDInvalid, typ: types.Invalid}

// Format creates a debug string for this Value using the data stored in Builder.
func (v Value) Format(b Builder) string {
	if annotation, ok := b.(*builder).valueAnnotations[v.ID()]; ok {
		return annotation
	}
	return fmt.Sprintf("v%d", v.ID())
}

func (v Value) formatWithType(b Builder) (ret string) {
	if annotation, ok := b.(*builder).valueAnnotations[v.ID()]; ok {
		ret = annotation + ":" + v.Type().String()
	} else {
		ret = fmt.Sprintf("v%d:%s", v.ID(), v.Type())
	}
	return ret
}

// Valid returns true if this value is valid.
func (v Value) Valid() bool {
	return v.ID() != valueIDInvalid
}

// Type returns the Type of this value.
func (v Value) Type() *types.Type {
	return v.typ
}

// ID returns the valueID of this value.
func (v Value) ID() ValueID {
	return ValueID(v.id)
}

// setType sets a type to this Value and returns the updated Value.
func (v Value) setType(typ *types.Type) Value {
	v.typ = typ
	return v
}

// setInstructionID sets an Instruction.id to this Value and returns the updated Value.
func (v Value) setInstructionID(id int) Value {
	v.instID = int32(id)
	return v
}

// instructionID() returns the Instruction.id of this Value.
func (v Value) instructionID() int {
	return int(v.instID)
}

func (v Value) BlockID() BasicBlockID {
	if v.typ != types.Block {
		panic("BUG: not a block value")
	}
	return BasicBlockID(v.id)
}

func (v Value) FuncRef() FuncRef {
	if v.typ != types.Func {
		panic("BUG: not a func value")
	}
	return FuncRef(v.id)
}

func ValueFromBlockID(id BasicBlockID) Value {
	return Value{
		id:     ValueID(id),
		instID: -1,
		typ:    types.Block,
	}
}

func ValueFromFuncRef(f FuncRef) Value {
	return Value{
		id:     ValueID(f),
		instID: -1,
		typ:    types.Func,
	}
}
