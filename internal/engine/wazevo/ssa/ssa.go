// Package ssa is used to construct SSA function. By nature this is free of Wasm specific thing
// and ISA.
//
// We use the "block argument" variant of SSA: https://en.wikipedia.org/wiki/Static_single-assignment_form#Block_arguments
// which is equivalent to the traditional PHI function based one, but more convenient during optimizations.
// However, in this package's source code comment, we might use PHI whenever it seems necessary in order to be aligned with
// existing literatures, e.g. SSA level optimization algorithms are often described using PHI nodes.
//
// The rationale doc for the choice of "block argument" by MLIR of LLVM is worth a read:
// https://mlir.llvm.org/docs/Rationale/Rationale/#block-arguments-vs-phi-nodes
//
// The algorithm to resolve variable definitions used here is based on the paper
// "Simple and Efficient Construction of Static Single Assignment Form": https://link.springer.com/content/pdf/10.1007/978-3-642-37051-9_6.pdf.
package ssa

import (
	"fmt"
	"math"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
)

// FuncRef is a unique identifier for a function of the frontend,
// and is used to reference the function in function call.
type FuncRef uint32

// String implements fmt.Stringer.
func (r FuncRef) String() string {
	return fmt.Sprintf("f%d", r)
}

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

// Var represents an SSA value with a type information. The relationship with Variable is 1: N (including 0),
// that means there might be multiple Variable(s) for a Var.
//
// 32 to 59-bit is used to store the unique identifier of the Instruction that generates this value if any.
// 60 to 63-bit is used to store Type for this value.
type Var struct {
	id     VarID
	instID int32
	typ    *types.Type
}

// VarID is the lower 32bit of Value, which is the pure identifier of Value without type info.
type VarID uint32

const valueIDInvalid VarID = math.MaxUint32

var InvalidVar = Var{id: valueIDInvalid, typ: types.Invalid}

// Format creates a debug string for this Value using the data stored in Builder.
func (v Var) Format(b *Builder) string {
	if annotation, ok := b.valueAnnotations[v.ID()]; ok {
		return annotation
	}
	return fmt.Sprintf("v%d", v.ID())
}

func (v Var) formatWithType(b *Builder) (ret string) {
	if annotation, ok := b.valueAnnotations[v.ID()]; ok {
		ret = annotation + ":" + v.Type().String()
	} else {
		ret = fmt.Sprintf("v%d:%s", v.ID(), v.Type())
	}
	return ret
}

// Valid returns true if this value is valid.
func (v Var) Valid() bool {
	return v.ID() != valueIDInvalid
}

// Type returns the Type of this value.
func (v Var) Type() *types.Type {
	return v.typ
}

// ID returns the valueID of this value.
func (v Var) ID() VarID {
	return VarID(v.id)
}

// setType sets a type to this Value and returns the updated Value.
func (v Var) setType(typ *types.Type) Var {
	v.typ = typ
	return v
}

// setInstructionID sets an Instruction.id to this Value and returns the updated Value.
func (v Var) setInstructionID(id int) Var {
	v.instID = int32(id)
	return v
}

// instructionID() returns the Instruction.id of this Value.
func (v Var) instructionID() int {
	return int(v.instID)
}

func (v Var) BlockID() BasicBlockID {
	if v.typ != types.Block {
		panic("BUG: not a block value")
	}
	return BasicBlockID(v.id)
}

func (v Var) FuncRef() FuncRef {
	if v.typ != types.Func {
		panic("BUG: not a func value")
	}
	return FuncRef(v.id)
}

func VarFromBlockID(id BasicBlockID) Var {
	return Var{
		id:     VarID(id),
		instID: -1,
		typ:    types.Block,
	}
}

func VarFromFuncRef(f FuncRef) Var {
	return Var{
		id:     VarID(f),
		instID: -1,
		typ:    types.Func,
	}
}
