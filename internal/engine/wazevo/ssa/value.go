package ssa

import (
	"fmt"
	"math"
	"strings"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
)

// Opcode represents a SSA instruction.
type Opcode uint32

// Value represents an instruction whose opcode is specified by
// Opcode. Since Go doesn't have union type, we use this flattened type
// for all instructions, and therefore each field has different meaning
// depending on Opcode.
type Value struct {
	// id is the unique ID of this instruction which ascends from 0 following the order of program.
	id     int
	opcode Opcode
	Args   []Var
	Type   *types.Type
	u1, u2 uint64

	// Return is the (first) return value of this instruction.
	// For branching instructions except for OpcodeBrTable, they hold BlockID to jump cast to Value.
	Return         Var
	gid            InstructionGroupID
	sourceOffset   SourceOffset
	live           bool
	alreadyLowered bool

	argStorage [4]Var // preallocated storage for ArgSlice to avoid allocation for common cases
}

// SourceOffset represents the offset of the source of an instruction.
type SourceOffset int64

const sourceOffsetUnknown = -1

// Valid returns true if this source offset is valid.
func (l SourceOffset) Valid() bool {
	return l != sourceOffsetUnknown
}

func (i *Value) annotateSourceOffset(line SourceOffset) {
	i.sourceOffset = line
}

// SourceOffset returns the source offset of this instruction.
func (i *Value) SourceOffset() SourceOffset {
	return i.sourceOffset
}

// Opcode returns the opcode of this instruction.
func (i *Value) Opcode() Opcode {
	return i.opcode
}

// GroupID returns the InstructionGroupID of this instruction.
func (i *Value) GroupID() InstructionGroupID {
	return i.gid
}

// MarkLowered marks this instruction as already lowered.
func (i *Value) MarkLowered() {
	i.alreadyLowered = true
}

// Lowered returns true if this instruction is already lowered.
func (i *Value) Lowered() bool {
	return i.alreadyLowered
}

// resetValue resets this value to the initial state.
func resetValue(i *Value) {
	*i = Value{}
	i.Args = i.argStorage[:0]
	i.Return = InvalidVar
	i.Type = types.Invalid
	i.sourceOffset = sourceOffsetUnknown
	for idx := range i.argStorage {
		i.argStorage[idx] = InvalidVar
	}
}

// InstructionGroupID is assigned to each instruction and represents a group of instructions
// where each instruction is interchangeable with others except for the last instruction
// in the group which has side effects. In short, InstructionGroupID is determined by the side effects of instructions.
// That means, if there's an instruction with side effect between two instructions, then these two instructions
// will have different instructionGroupID. Note that each block always ends with branching, which is with side effects,
// therefore, instructions in different blocks always have different InstructionGroupID(s).
//
// The notable application of this is used in lowering SSA-level instruction to a ISA specific instruction,
// where we eagerly try to merge multiple instructions into single operation etc. Such merging cannot be done
// if these instruction have different InstructionGroupID since it will change the semantics of a program.
//
// See passDeadCodeElimination.
type InstructionGroupID uint32

// ArgWithLane returns the first argument to this instruction, and the lane type.
func (i *Value) ArgWithLane() (Var, types.VecLane) {
	return i.Args[0], types.VecLane(i.u1)
}

// Arg2WithLane returns the first two arguments to this instruction, and the lane type.
func (i *Value) Arg2WithLane() (Var, Var, types.VecLane) {
	return i.Args[0], i.Args[1], types.VecLane(i.u1)
}

// ShuffleData returns the first two arguments to this instruction and 2 uint64s `lo`, `hi`.
//
// Note: Each uint64 encodes a sequence of 8 bytes where each byte encodes a types.VecLane,
// so that the 128bit integer `hi<<64|lo` packs a slice `[16]types.VecLane`,
// where `lane[0]` is the least significant byte, and `lane[n]` is shifted to offset `n*8`.
func (i *Value) ShuffleData() (v Var, v2 Var, lo uint64, hi uint64) {
	return i.Args[0], i.Args[1], i.u1, i.u2
}

// Arg3 returns the first three arguments to this instruction.
func (i *Value) Arg3() (Var, Var, Var) {
	return i.Args[0], i.Args[1], i.Args[2]
}

func (i *Value) setArg1(x Var) {
	i.Args = i.argStorage[:0]
	i.Args = append(i.Args, x)
}

func (i *Value) setArg2(x, y Var) {
	i.Args = i.argStorage[:0]
	i.Args = append(i.Args, x, y)
}

func (i *Value) setArg3(x, y, z Var) {
	i.Args = i.argStorage[:0]
	i.Args = append(i.Args, x, y, z)
}

// AtomicRmwOp represents the atomic read-modify-write operation.
type AtomicRmwOp byte

const (
	// AtomicRmwOpAdd is an atomic add operation.
	AtomicRmwOpAdd AtomicRmwOp = iota
	// AtomicRmwOpSub is an atomic sub operation.
	AtomicRmwOpSub
	// AtomicRmwOpAnd is an atomic and operation.
	AtomicRmwOpAnd
	// AtomicRmwOpOr is an atomic or operation.
	AtomicRmwOpOr
	// AtomicRmwOpXor is an atomic xor operation.
	AtomicRmwOpXor
	// AtomicRmwOpXchg is an atomic swap operation.
	AtomicRmwOpXchg
)

// String implements the fmt.Stringer.
func (op AtomicRmwOp) String() string {
	switch op {
	case AtomicRmwOpAdd:
		return "add"
	case AtomicRmwOpSub:
		return "sub"
	case AtomicRmwOpAnd:
		return "and"
	case AtomicRmwOpOr:
		return "or"
	case AtomicRmwOpXor:
		return "xor"
	case AtomicRmwOpXchg:
		return "xchg"
	}
	panic(fmt.Sprintf("unknown AtomicRmwOp: %d", op))
}

// AsLoad initializes this instruction as a store instruction with OpcodeLoad.
func (i *Value) AsLoad(ptr Var, offset uint32, typ *types.Type) *Value {
	i.opcode = OpcodeLoad
	i.setArg1(ptr)
	i.u1 = uint64(offset)
	i.Type = typ
	return i
}

// AsExtLoad initializes this instruction as a store instruction with OpcodeLoad.
func (i *Value) AsExtLoad(op Opcode, ptr Var, offset uint32, dst64bit bool) *Value {
	i.opcode = op
	i.setArg1(ptr)
	i.u1 = uint64(offset)
	if dst64bit {
		i.Type = types.I64
	} else {
		i.Type = types.I32
	}
	return i
}

// AsVZeroExtLoad initializes this instruction as a store instruction with OpcodeVExtLoad.
func (i *Value) AsVZeroExtLoad(ptr Var, offset uint32, scalarType *types.Type) *Value {
	i.opcode = OpcodeVZeroExtLoad
	i.setArg2(ptr, Var{typ: scalarType})
	i.u1 = uint64(offset)
	i.Type = types.V128
	return i
}

// VZeroExtLoadData returns the operands for a load instruction. The returned `typ` is the scalar type of the load target.
func (i *Value) VZeroExtLoadData() (ptr Var, offset uint32, typ *types.Type) {
	return i.Args[0], uint32(i.u1), i.Args[1].Type()
}

// AsLoadSplat initializes this instruction as a store instruction with OpcodeLoadSplat.
func (i *Value) AsLoadSplat(ptr Var, offset uint32, lane types.VecLane) *Value {
	i.opcode = OpcodeLoadSplat
	i.setArg1(ptr)
	i.u1 = uint64(offset)
	i.u2 = uint64(lane)
	i.Type = types.V128
	return i
}

// LoadData returns the operands for a load instruction.
func (i *Value) LoadData() (ptr Var, offset uint32, typ *types.Type) {
	return i.Args[0], uint32(i.u1), i.Type
}

// LoadSplatData returns the operands for a load splat instruction.
func (i *Value) LoadSplatData() (ptr Var, offset uint32, lane types.VecLane) {
	return i.Args[0], uint32(i.u1), types.VecLane(i.u2)
}

// AsStore initializes this instruction as a store instruction with OpcodeStore.
func (i *Value) AsStore(storeOp Opcode, value, ptr Var, offset uint32) *Value {
	i.opcode = storeOp
	i.setArg2(value, ptr)

	var dstSize uint64
	switch storeOp {
	case OpcodeStore:
		dstSize = uint64(value.Type().Bits())
	case OpcodeIstore8:
		dstSize = 8
	case OpcodeIstore16:
		dstSize = 16
	case OpcodeIstore32:
		dstSize = 32
	default:
		panic("invalid store opcode" + storeOp.String())
	}
	i.u1 = uint64(offset) | dstSize<<32
	return i
}

// StoreData returns the operands for a store instruction.
func (i *Value) StoreData() (value, ptr Var, offset uint32, storeSizeInBits byte) {
	return i.Args[0], i.Args[1], uint32(i.u1), byte(i.u1 >> 32)
}

// AsIconst64 initializes this instruction as a 64-bit integer constant instruction with OpcodeIconst.
func (i *Value) AsIconst64(v uint64) *Value {
	i.opcode = OpcodeIconst
	i.Type = types.I64
	i.u1 = v
	return i
}

// AsIconst32 initializes this instruction as a 32-bit integer constant instruction with OpcodeIconst.
func (i *Value) AsIconst32(v uint32) *Value {
	i.opcode = OpcodeIconst
	i.Type = types.I32
	i.u1 = uint64(v)
	return i
}

// AsIadd initializes this instruction as an integer addition instruction with OpcodeIadd.
func (i *Value) AsIadd(x, y Var) *Value {
	i.opcode = OpcodeIadd
	i.setArg2(x, y)
	i.Type = x.Type()
	return i
}

// AsVIadd initializes this instruction as an integer addition instruction with OpcodeVIadd on a vector.
func (i *Value) AsVIadd(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVIadd
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsWideningPairwiseDotProductS initializes this instruction as a lane-wise integer extended pairwise addition instruction
// with OpcodeIaddPairwise on a vector.
func (i *Value) AsWideningPairwiseDotProductS(x, y Var) *Value {
	i.opcode = OpcodeWideningPairwiseDotProductS
	i.setArg2(x, y)
	i.Type = types.V128
	return i
}

// AsExtIaddPairwise initializes this instruction as a lane-wise integer extended pairwise addition instruction
// with OpcodeIaddPairwise on a vector.
func (i *Value) AsExtIaddPairwise(x Var, srcLane types.VecLane, signed bool) *Value {
	i.opcode = OpcodeExtIaddPairwise
	i.setArg1(x)
	i.u1 = uint64(srcLane)
	if signed {
		i.u2 = 1
	}
	i.Type = types.V128
	return i
}

// ExtIaddPairwiseData returns the operands for a lane-wise integer extended pairwise addition instruction.
func (i *Value) ExtIaddPairwiseData() (x Var, srcLane types.VecLane, signed bool) {
	return i.Args[0], types.VecLane(i.u1), i.u2 != 0
}

// AsVSaddSat initializes this instruction as a vector addition with saturation instruction with OpcodeVSaddSat on a vector.
func (i *Value) AsVSaddSat(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVSaddSat
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVUaddSat initializes this instruction as a vector addition with saturation instruction with OpcodeVUaddSat on a vector.
func (i *Value) AsVUaddSat(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVUaddSat
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVIsub initializes this instruction as an integer subtraction instruction with OpcodeVIsub on a vector.
func (i *Value) AsVIsub(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVIsub
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVSsubSat initializes this instruction as a vector addition with saturation instruction with OpcodeVSsubSat on a vector.
func (i *Value) AsVSsubSat(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVSsubSat
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVUsubSat initializes this instruction as a vector addition with saturation instruction with OpcodeVUsubSat on a vector.
func (i *Value) AsVUsubSat(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVUsubSat
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVImin initializes this instruction as a signed integer min instruction with OpcodeVImin on a vector.
func (i *Value) AsVImin(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVImin
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVUmin initializes this instruction as an unsigned integer min instruction with OpcodeVUmin on a vector.
func (i *Value) AsVUmin(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVUmin
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVImax initializes this instruction as a signed integer max instruction with OpcodeVImax on a vector.
func (i *Value) AsVImax(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVImax
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVUmax initializes this instruction as an unsigned integer max instruction with OpcodeVUmax on a vector.
func (i *Value) AsVUmax(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVUmax
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVAvgRound initializes this instruction as an unsigned integer avg instruction, truncating to zero with OpcodeVAvgRound on a vector.
func (i *Value) AsVAvgRound(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVAvgRound
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVImul initializes this instruction as an integer multiplication with OpcodeVImul on a vector.
func (i *Value) AsVImul(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVImul
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsSqmulRoundSat initializes this instruction as a lane-wise saturating rounding multiplication
// in Q15 format with OpcodeSqmulRoundSat on a vector.
func (i *Value) AsSqmulRoundSat(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeSqmulRoundSat
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVIabs initializes this instruction as a vector absolute value with OpcodeVIabs.
func (i *Value) AsVIabs(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVIabs
	i.setArg1(x)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVIneg initializes this instruction as a vector negation with OpcodeVIneg.
func (i *Value) AsVIneg(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVIneg
	i.setArg1(x)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVIpopcnt initializes this instruction as a Population Count instruction with OpcodeVIpopcnt on a vector.
func (i *Value) AsVIpopcnt(x Var, lane types.VecLane) *Value {
	if lane != types.VecLaneI8x16 {
		panic("Unsupported lane type " + lane.String())
	}
	i.opcode = OpcodeVIpopcnt
	i.setArg1(x)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVSqrt initializes this instruction as a sqrt instruction with OpcodeVSqrt on a vector.
func (i *Value) AsVSqrt(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVSqrt
	i.setArg1(x)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFabs initializes this instruction as a float abs instruction with OpcodeVFabs on a vector.
func (i *Value) AsVFabs(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFabs
	i.setArg1(x)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFneg initializes this instruction as a float neg instruction with OpcodeVFneg on a vector.
func (i *Value) AsVFneg(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFneg
	i.setArg1(x)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFmax initializes this instruction as a float max instruction with OpcodeVFmax on a vector.
func (i *Value) AsVFmax(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFmax
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFmin initializes this instruction as a float min instruction with OpcodeVFmin on a vector.
func (i *Value) AsVFmin(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFmin
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFadd initializes this instruction as a floating point add instruction with OpcodeVFadd on a vector.
func (i *Value) AsVFadd(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFadd
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFsub initializes this instruction as a floating point subtraction instruction with OpcodeVFsub on a vector.
func (i *Value) AsVFsub(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFsub
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFmul initializes this instruction as a floating point multiplication instruction with OpcodeVFmul on a vector.
func (i *Value) AsVFmul(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFmul
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFdiv initializes this instruction as a floating point division instruction with OpcodeVFdiv on a vector.
func (i *Value) AsVFdiv(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFdiv
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsImul initializes this instruction as an integer addition instruction with OpcodeImul.
func (i *Value) AsImul(x, y Var) *Value {
	i.opcode = OpcodeImul
	i.setArg2(x, y)
	i.Type = x.Type()
	return i
}

func (i *Value) Insert(b *Builder) *Value {
	b.InsertInstruction(i)
	return i
}

// AsIsub initializes this instruction as an integer subtraction instruction with OpcodeIsub.
func (i *Value) AsIsub(x, y Var) *Value {
	i.opcode = OpcodeIsub
	i.setArg2(x, y)
	i.Type = x.Type()
	return i
}

// AsIcmp initializes this instruction as an integer comparison instruction with OpcodeIcmp.
func (i *Value) AsIcmp(x, y Var, c IntegerCmpCond) *Value {
	i.opcode = OpcodeIcmp
	i.setArg2(x, y)
	i.u1 = uint64(c)
	i.Type = types.I32
	return i
}

// AsFcmp initializes this instruction as an integer comparison instruction with OpcodeFcmp.
func (i *Value) AsFcmp(x, y Var, c FloatCmpCond) {
	i.opcode = OpcodeFcmp
	i.setArg2(x, y)
	i.u1 = uint64(c)
	i.Type = types.I32
}

// AsVIcmp initializes this instruction as an integer vector comparison instruction with OpcodeVIcmp.
func (i *Value) AsVIcmp(x, y Var, c IntegerCmpCond, lane types.VecLane) *Value {
	i.opcode = OpcodeVIcmp
	i.setArg2(x, y)
	i.u1 = uint64(c)
	i.u2 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsVFcmp initializes this instruction as a float comparison instruction with OpcodeVFcmp on Vector.
func (i *Value) AsVFcmp(x, y Var, c FloatCmpCond, lane types.VecLane) *Value {
	i.opcode = OpcodeVFcmp
	i.setArg2(x, y)
	i.u1 = uint64(c)
	i.Type = types.V128
	i.u2 = uint64(lane)
	return i
}

// AsVCeil initializes this instruction as an instruction with OpcodeCeil.
func (i *Value) AsVCeil(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVCeil
	i.setArg1(x)
	i.Type = x.Type()
	i.u1 = uint64(lane)
	return i
}

// AsVFloor initializes this instruction as an instruction with OpcodeFloor.
func (i *Value) AsVFloor(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVFloor
	i.setArg1(x)
	i.Type = x.Type()
	i.u1 = uint64(lane)
	return i
}

// AsVTrunc initializes this instruction as an instruction with OpcodeTrunc.
func (i *Value) AsVTrunc(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVTrunc
	i.setArg1(x)
	i.Type = x.Type()
	i.u1 = uint64(lane)
	return i
}

// AsVNearest initializes this instruction as an instruction with OpcodeNearest.
func (i *Value) AsVNearest(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVNearest
	i.setArg1(x)
	i.Type = x.Type()
	i.u1 = uint64(lane)
	return i
}

// AsVMaxPseudo initializes this instruction as an instruction with OpcodeVMaxPseudo.
func (i *Value) AsVMaxPseudo(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVMaxPseudo
	i.Type = x.Type()
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	return i
}

// AsVMinPseudo initializes this instruction as an instruction with OpcodeVMinPseudo.
func (i *Value) AsVMinPseudo(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVMinPseudo
	i.Type = x.Type()
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	return i
}

// AsSDiv initializes this instruction as an integer bitwise and instruction with OpcodeSdiv.
func (i *Value) AsSDiv(x, y, ctx Var) *Value {
	i.opcode = OpcodeSdiv
	i.setArg3(x, y, ctx)
	i.Type = x.Type()
	return i
}

// AsUDiv initializes this instruction as an integer bitwise and instruction with OpcodeUdiv.
func (i *Value) AsUDiv(x, y, ctx Var) *Value {
	i.opcode = OpcodeUdiv
	i.setArg3(x, y, ctx)
	i.Type = x.Type()
	return i
}

// AsSRem initializes this instruction as an integer bitwise and instruction with OpcodeSrem.
func (i *Value) AsSRem(x, y, ctx Var) *Value {
	i.opcode = OpcodeSrem
	i.setArg3(x, y, ctx)
	i.Type = x.Type()
	return i
}

// AsURem initializes this instruction as an integer bitwise and instruction with OpcodeUrem.
func (i *Value) AsURem(x, y, ctx Var) *Value {
	i.opcode = OpcodeUrem
	i.setArg3(x, y, ctx)
	i.Type = x.Type()
	return i
}

// AsBand initializes this instruction as an integer bitwise and instruction with OpcodeBand.
func (i *Value) AsBand(x, amount Var) *Value {
	i.opcode = OpcodeBand
	i.setArg2(x, amount)
	i.Type = x.Type()
	return i
}

// AsBor initializes this instruction as an integer bitwise or instruction with OpcodeBor.
func (i *Value) AsBor(x, amount Var) {
	i.opcode = OpcodeBor
	i.setArg2(x, amount)
	i.Type = x.Type()
}

// AsBxor initializes this instruction as an integer bitwise xor instruction with OpcodeBxor.
func (i *Value) AsBxor(x, amount Var) {
	i.opcode = OpcodeBxor
	i.setArg2(x, amount)
	i.Type = x.Type()
}

// AsIshl initializes this instruction as an integer shift left instruction with OpcodeIshl.
func (i *Value) AsIshl(x, amount Var) *Value {
	i.opcode = OpcodeIshl
	i.setArg2(x, amount)
	i.Type = x.Type()
	return i
}

// AsVIshl initializes this instruction as an integer shift left instruction with OpcodeVIshl on vector.
func (i *Value) AsVIshl(x, amount Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVIshl
	i.setArg2(x, amount)
	i.u1 = uint64(lane)
	i.Type = x.Type()
	return i
}

// AsUshr initializes this instruction as an integer unsigned shift right (logical shift right) instruction with OpcodeUshr.
func (i *Value) AsUshr(x, amount Var) *Value {
	i.opcode = OpcodeUshr
	i.setArg2(x, amount)
	i.Type = x.Type()
	return i
}

// AsVUshr initializes this instruction as an integer unsigned shift right (logical shift right) instruction with OpcodeVUshr on vector.
func (i *Value) AsVUshr(x, amount Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVUshr
	i.setArg2(x, amount)
	i.u1 = uint64(lane)
	i.Type = x.Type()
	return i
}

// AsSshr initializes this instruction as an integer signed shift right (arithmetic shift right) instruction with OpcodeSshr.
func (i *Value) AsSshr(x, amount Var) *Value {
	i.opcode = OpcodeSshr
	i.setArg2(x, amount)
	i.Type = x.Type()
	return i
}

// AsVSshr initializes this instruction as an integer signed shift right (arithmetic shift right) instruction with OpcodeVSshr on vector.
func (i *Value) AsVSshr(x, amount Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVSshr
	i.setArg2(x, amount)
	i.u1 = uint64(lane)
	i.Type = x.Type()
	return i
}

// AsExtractlane initializes this instruction as an extract lane instruction with OpcodeExtractlane on vector.
func (i *Value) AsExtractlane(x Var, index byte, lane types.VecLane, signed bool) *Value {
	i.opcode = OpcodeExtractlane
	i.setArg1(x)
	// We do not have a field for signedness, but `index` is a byte,
	// so we just encode the flag in the high bits of `u1`.
	i.u1 = uint64(index)
	if signed {
		i.u1 = i.u1 | 1<<32
	}
	i.u2 = uint64(lane)
	switch lane {
	case types.VecLaneI8x16, types.VecLaneI16x8, types.VecLaneI32x4:
		i.Type = types.I32
	case types.VecLaneI64x2:
		i.Type = types.I64
	case types.VecLaneF32x4:
		i.Type = types.F32
	case types.VecLaneF64x2:
		i.Type = types.F64
	}
	return i
}

// AsInsertlane initializes this instruction as an insert lane instruction with OpcodeInsertlane on vector.
func (i *Value) AsInsertlane(x, y Var, index byte, lane types.VecLane) *Value {
	i.opcode = OpcodeInsertlane
	i.setArg2(x, y)
	i.u1 = uint64(index)
	i.u2 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsShuffle initializes this instruction as a shuffle instruction with OpcodeShuffle on vector.
func (i *Value) AsShuffle(x, y Var, lane []byte) *Value {
	i.opcode = OpcodeShuffle
	i.setArg2(x, y)
	// Encode the 16 bytes as 8 bytes in u1, and 8 bytes in u2.
	i.u1 = uint64(lane[7])<<56 | uint64(lane[6])<<48 | uint64(lane[5])<<40 | uint64(lane[4])<<32 | uint64(lane[3])<<24 | uint64(lane[2])<<16 | uint64(lane[1])<<8 | uint64(lane[0])
	i.u2 = uint64(lane[15])<<56 | uint64(lane[14])<<48 | uint64(lane[13])<<40 | uint64(lane[12])<<32 | uint64(lane[11])<<24 | uint64(lane[10])<<16 | uint64(lane[9])<<8 | uint64(lane[8])
	i.Type = types.V128
	return i
}

// AsSwizzle initializes this instruction as an insert lane instruction with OpcodeSwizzle on vector.
func (i *Value) AsSwizzle(x, y Var, lane types.VecLane) *Value {
	i.opcode = OpcodeSwizzle
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsSplat initializes this instruction as an insert lane instruction with OpcodeSplat on vector.
func (i *Value) AsSplat(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeSplat
	i.setArg1(x)
	i.u1 = uint64(lane)
	i.Type = types.V128
	return i
}

// AsRotl initializes this instruction as a word rotate left instruction with OpcodeRotl.
func (i *Value) AsRotl(x, amount Var) {
	i.opcode = OpcodeRotl
	i.setArg2(x, amount)
	i.Type = x.Type()
}

// AsRotr initializes this instruction as a word rotate right instruction with OpcodeRotr.
func (i *Value) AsRotr(x, amount Var) {
	i.opcode = OpcodeRotr
	i.setArg2(x, amount)
	i.Type = x.Type()
}

// IcmpData returns the operands and comparison condition of this integer comparison instruction.
func (i *Value) IcmpData() (x, y Var, c IntegerCmpCond) {
	return i.Args[0], i.Args[1], IntegerCmpCond(i.u1)
}

// FcmpData returns the operands and comparison condition of this floating-point comparison instruction.
func (i *Value) FcmpData() (x, y Var, c FloatCmpCond) {
	return i.Args[0], i.Args[1], FloatCmpCond(i.u1)
}

// VIcmpData returns the operands and comparison condition of this integer comparison instruction on vector.
func (i *Value) VIcmpData() (x, y Var, c IntegerCmpCond, l types.VecLane) {
	return i.Args[0], i.Args[1], IntegerCmpCond(i.u1), types.VecLane(i.u2)
}

// VFcmpData returns the operands and comparison condition of this float comparison instruction on vector.
func (i *Value) VFcmpData() (x, y Var, c FloatCmpCond, l types.VecLane) {
	return i.Args[0], i.Args[1], FloatCmpCond(i.u1), types.VecLane(i.u2)
}

// ExtractlaneData returns the operands and sign flag of Extractlane on vector.
func (i *Value) ExtractlaneData() (x Var, index byte, signed bool, l types.VecLane) {
	x = i.Args[0]
	index = byte(0b00001111 & i.u1)
	signed = i.u1>>32 != 0
	l = types.VecLane(i.u2)
	return
}

// InsertlaneData returns the operands and sign flag of Insertlane on vector.
func (i *Value) InsertlaneData() (x, y Var, index byte, l types.VecLane) {
	x = i.Args[0]
	y = i.Args[1]
	index = byte(i.u1)
	l = types.VecLane(i.u2)
	return
}

// AsFadd initializes this instruction as a floating-point addition instruction with OpcodeFadd.
func (i *Value) AsFadd(x, y Var) {
	i.opcode = OpcodeFadd
	i.setArg2(x, y)
	i.Type = x.Type()
}

// AsFsub initializes this instruction as a floating-point subtraction instruction with OpcodeFsub.
func (i *Value) AsFsub(x, y Var) {
	i.opcode = OpcodeFsub
	i.setArg2(x, y)
	i.Type = x.Type()
}

// AsFmul initializes this instruction as a floating-point multiplication instruction with OpcodeFmul.
func (i *Value) AsFmul(x, y Var) {
	i.opcode = OpcodeFmul
	i.setArg2(x, y)
	i.Type = x.Type()
}

// AsFdiv initializes this instruction as a floating-point division instruction with OpcodeFdiv.
func (i *Value) AsFdiv(x, y Var) {
	i.opcode = OpcodeFdiv
	i.setArg2(x, y)
	i.Type = x.Type()
}

// AsFmin initializes this instruction to take the minimum of two floating-points with OpcodeFmin.
func (i *Value) AsFmin(x, y Var) {
	i.opcode = OpcodeFmin
	i.setArg2(x, y)
	i.Type = x.Type()
}

// AsFmax initializes this instruction to take the maximum of two floating-points with OpcodeFmax.
func (i *Value) AsFmax(x, y Var) {
	i.opcode = OpcodeFmax
	i.setArg2(x, y)
	i.Type = x.Type()
}

// AsF32const initializes this instruction as a 32-bit floating-point constant instruction with OpcodeF32const.
func (i *Value) AsF32const(f float32) *Value {
	i.opcode = OpcodeF32const
	i.Type = types.F64
	i.u1 = uint64(math.Float32bits(f))
	return i
}

// AsF64const initializes this instruction as a 64-bit floating-point constant instruction with OpcodeF64const.
func (i *Value) AsF64const(f float64) *Value {
	i.opcode = OpcodeF64const
	i.Type = types.F64
	i.u1 = math.Float64bits(f)
	return i
}

// AsVconst initializes this instruction as a vector constant instruction with OpcodeVconst.
func (i *Value) AsVconst(lo, hi uint64) *Value {
	i.opcode = OpcodeVconst
	i.Type = types.V128
	i.u1 = lo
	i.u2 = hi
	return i
}

// AsVbnot initializes this instruction as a vector negation instruction with OpcodeVbnot.
func (i *Value) AsVbnot(v Var) *Value {
	i.opcode = OpcodeVbnot
	i.Type = types.V128
	i.setArg1(v)
	return i
}

// AsVband initializes this instruction as an and vector instruction with OpcodeVband.
func (i *Value) AsVband(x, y Var) *Value {
	i.opcode = OpcodeVband
	i.Type = types.V128
	i.setArg2(x, y)
	return i
}

// AsVbor initializes this instruction as an or vector instruction with OpcodeVbor.
func (i *Value) AsVbor(x, y Var) *Value {
	i.opcode = OpcodeVbor
	i.Type = types.V128
	i.setArg2(x, y)
	return i
}

// AsVbxor initializes this instruction as a xor vector instruction with OpcodeVbxor.
func (i *Value) AsVbxor(x, y Var) *Value {
	i.opcode = OpcodeVbxor
	i.Type = types.V128
	i.setArg2(x, y)
	return i
}

// AsVbandnot initializes this instruction as an and-not vector instruction with OpcodeVbandnot.
func (i *Value) AsVbandnot(x, y Var) *Value {
	i.opcode = OpcodeVbandnot
	i.Type = types.V128
	i.setArg2(x, y)
	return i
}

// AsVbitselect initializes this instruction as a bit select vector instruction with OpcodeVbitselect.
func (i *Value) AsVbitselect(c, x, y Var) *Value {
	i.opcode = OpcodeVbitselect
	i.Type = types.V128
	i.setArg3(c, x, y)
	return i
}

// AsVanyTrue initializes this instruction as an anyTrue vector instruction with OpcodeVanyTrue.
func (i *Value) AsVanyTrue(x Var) *Value {
	i.opcode = OpcodeVanyTrue
	i.Type = types.I32
	i.setArg1(x)
	return i
}

// AsVallTrue initializes this instruction as an allTrue vector instruction with OpcodeVallTrue.
func (i *Value) AsVallTrue(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVallTrue
	i.Type = types.I32
	i.setArg1(x)
	i.u1 = uint64(lane)
	return i
}

// AsVhighBits initializes this instruction as a highBits vector instruction with OpcodeVhighBits.
func (i *Value) AsVhighBits(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeVhighBits
	i.Type = types.I32
	i.setArg1(x)
	i.u1 = uint64(lane)
	return i
}

// VconstData returns the operands of this vector constant instruction.
func (i *Value) VconstData() (lo, hi uint64) {
	return i.u1, i.u2
}

// AsReturn initializes this instruction as a return instruction with OpcodeReturn.
func (i *Value) AsReturn(vs []Var) *Value {
	i.opcode = OpcodeReturn
	i.Args = vs
	return i
}

// AsIreduce initializes this instruction as a reduction instruction with OpcodeIreduce.
func (i *Value) AsIreduce(v Var, dstType *types.Type) *Value {
	i.opcode = OpcodeIreduce
	i.setArg1(v)
	i.Type = dstType
	return i
}

// AsWiden initializes this instruction as a signed or unsigned widen instruction
// on low half or high half of the given vector with OpcodeSwidenLow, OpcodeUwidenLow, OpcodeSwidenHigh, OpcodeUwidenHigh.
func (i *Value) AsWiden(v Var, lane types.VecLane, signed, low bool) *Value {
	switch {
	case signed && low:
		i.opcode = OpcodeSwidenLow
	case !signed && low:
		i.opcode = OpcodeUwidenLow
	case signed && !low:
		i.opcode = OpcodeSwidenHigh
	case !signed && !low:
		i.opcode = OpcodeUwidenHigh
	}
	i.setArg1(v)
	i.u1 = uint64(lane)
	return i
}

// AsAtomicLoad initializes this instruction as an atomic load.
// The size is in bytes and must be 1, 2, 4, or 8.
func (i *Value) AsAtomicLoad(addr Var, size uint64, typ *types.Type) *Value {
	i.opcode = OpcodeAtomicLoad
	i.u1 = size
	i.setArg1(addr)
	i.Type = typ
	return i
}

// AsAtomicLoad initializes this instruction as an atomic store.
// The size is in bytes and must be 1, 2, 4, or 8.
func (i *Value) AsAtomicStore(addr, val Var, size uint64) *Value {
	i.opcode = OpcodeAtomicStore
	i.u1 = size
	i.setArg2(addr, val)
	i.Type = val.Type()
	return i
}

// AsAtomicRmw initializes this instruction as an atomic read-modify-write.
// The size is in bytes and must be 1, 2, 4, or 8.
func (i *Value) AsAtomicRmw(op AtomicRmwOp, addr, val Var, size uint64) *Value {
	i.opcode = OpcodeAtomicRmw
	i.u1 = uint64(op)
	i.u2 = size
	i.setArg2(addr, val)
	i.Type = val.Type()
	return i
}

// AsAtomicCas initializes this instruction as an atomic compare-and-swap.
// The size is in bytes and must be 1, 2, 4, or 8.
func (i *Value) AsAtomicCas(addr, exp, repl Var, size uint64) *Value {
	i.opcode = OpcodeAtomicCas
	i.u1 = size
	i.setArg3(addr, exp, repl)
	i.Type = repl.Type()
	return i
}

// AsFence initializes this instruction as a memory fence.
// A single byte immediate may be used to indicate fence ordering in the future
// but is currently always 0 and ignored.
func (i *Value) AsFence(order byte) *Value {
	i.opcode = OpcodeFence
	i.u1 = uint64(order)
	return i
}

// AtomicRmwData returns the data for this atomic read-modify-write instruction.
func (i *Value) AtomicRmwData() (op AtomicRmwOp, size uint64) {
	return AtomicRmwOp(i.u1), i.u2
}

// AtomicTargetSize returns the target memory size of the atomic instruction.
func (i *Value) AtomicTargetSize() (size uint64) {
	return i.u1
}

// AsTailCallReturnCall initializes this instruction as a call instruction with OpcodeTailCallReturnCall.
func (i *Value) AsTailCallReturnCall(ref FuncRef, sig *types.Signature, args []Var) {
	i.opcode = OpcodeTailCallReturnCall
	i.u1 = uint64(ref)
	i.Args = args
	i.u2 = uint64(sig.ID)
	sig.Used = true
}

// AsTailCallReturnCallIndirect initializes this instruction as a call-indirect instruction with OpcodeTailCallReturnCallIndirect.
func (i *Value) AsTailCallReturnCallIndirect(funcPtr Var, sig *types.Signature, args []Var) *Value {
	i.opcode = OpcodeTailCallReturnCallIndirect
	i.setArg1(funcPtr)
	i.Args = append(i.Args, args...)
	i.u1 = uint64(sig.ID)
	sig.Used = true
	return i
}

// ReturnVals returns the return values of OpcodeReturn.
func (i *Value) ReturnVals() []Var {
	return i.Args
}

// AsExitWithCode initializes this instruction as a trap instruction with OpcodeExitWithCode.
func (i *Value) AsExitWithCode(ctx Var, code wazevoapi.ExitCode) {
	i.opcode = OpcodeExitWithCode
	i.setArg1(ctx)
	i.u1 = uint64(code)
}

// AsExitIfTrueWithCode initializes this instruction as a trap instruction with OpcodeExitIfTrueWithCode.
func (i *Value) AsExitIfTrueWithCode(ctx, c Var, code wazevoapi.ExitCode) *Value {
	i.opcode = OpcodeExitIfTrueWithCode
	i.setArg2(ctx, c)
	i.u1 = uint64(code)
	return i
}

// ExitWithCodeData returns the context and exit code of OpcodeExitWithCode.
func (i *Value) ExitWithCodeData() (ctx Var, code wazevoapi.ExitCode) {
	return i.Args[0], wazevoapi.ExitCode(i.u1)
}

// ExitIfTrueWithCodeData returns the context and exit code of OpcodeExitWithCode.
func (i *Value) ExitIfTrueWithCodeData() (ctx, c Var, code wazevoapi.ExitCode) {
	return i.Args[0], i.Args[1], wazevoapi.ExitCode(i.u1)
}

// AsCall initializes this instruction as a call instruction with OpcodeCall.
func (i *Value) AsCall(ref FuncRef, sig *types.Signature, args []Var) {
	i.opcode = OpcodeCall
	i.u1 = uint64(ref)
	i.u2 = uint64(sig.ID)
	i.Args = args
	sig.Used = true
}

// CallData returns the call data for this instruction necessary for backends.
func (i *Value) CallData() (ref FuncRef, sigID types.SignatureID, args []Var) {
	if i.opcode != OpcodeCall && i.opcode != OpcodeTailCallReturnCall {
		panic("BUG: CallData only available for OpcodeCall")
	}
	ref = FuncRef(i.u1)
	sigID = types.SignatureID(i.u2)
	args = i.Args
	return
}

// AsCallIndirect initializes this instruction as a call-indirect instruction with OpcodeCallIndirect.
func (i *Value) AsCallIndirect(funcPtr Var, sig *types.Signature, args []Var) *Value {
	i.opcode = OpcodeCallIndirect
	i.Type = types.F64
	i.setArg1(funcPtr)
	i.Args = append(i.Args, args...)
	i.u1 = uint64(sig.ID)
	sig.Used = true
	return i
}

// AsCallGoRuntimeMemmove is the same as AsCallIndirect, but with a special flag set to indicate that it is a call to the Go runtime memmove function.
func (i *Value) AsCallGoRuntimeMemmove(funcPtr Var, sig *types.Signature, args []Var) *Value {
	i.AsCallIndirect(funcPtr, sig, args)
	i.u2 = 1
	return i
}

// CallIndirectData returns the call indirect data for this instruction necessary for backends.
func (i *Value) CallIndirectData() (funcPtr Var, sigID types.SignatureID, args []Var, isGoMemmove bool) {
	if i.opcode != OpcodeCallIndirect && i.opcode != OpcodeTailCallReturnCallIndirect {
		panic("BUG: CallIndirectData only available for OpcodeCallIndirect and OpcodeTailCallReturnCallIndirect")
	}
	funcPtr = i.Args[0]
	sigID = types.SignatureID(i.u1)
	args = i.Args[1:]
	isGoMemmove = i.u2 == 1
	return
}

func (i *Value) AsSelectTuple(v Var, index int) {
	i.opcode = OpcodeSelectTuple
	i.setArg1(v)
	i.u1 = uint64(index)
	i.Type = v.Type().At(index)
}

func (i *Value) SelectTupleData() (v Var, index int) {
	return i.Args[0], int(i.u1)
}

// AsClz initializes this instruction as a Count Leading Zeroes instruction with OpcodeClz.
func (i *Value) AsClz(x Var) {
	i.opcode = OpcodeClz
	i.setArg1(x)
	i.Type = x.Type()
}

// AsCtz initializes this instruction as a Count Trailing Zeroes instruction with OpcodeCtz.
func (i *Value) AsCtz(x Var) {
	i.opcode = OpcodeCtz
	i.setArg1(x)
	i.Type = x.Type()
}

// AsPopcnt initializes this instruction as a Population Count instruction with OpcodePopcnt.
func (i *Value) AsPopcnt(x Var) {
	i.opcode = OpcodePopcnt
	i.setArg1(x)
	i.Type = x.Type()
}

// AsFneg initializes this instruction as an instruction with OpcodeFneg.
func (i *Value) AsFneg(x Var) *Value {
	i.opcode = OpcodeFneg
	i.setArg1(x)
	i.Type = x.Type()
	return i
}

// AsSqrt initializes this instruction as an instruction with OpcodeSqrt.
func (i *Value) AsSqrt(x Var) *Value {
	i.opcode = OpcodeSqrt
	i.setArg1(x)
	i.Type = x.Type()
	return i
}

// AsFabs initializes this instruction as an instruction with OpcodeFabs.
func (i *Value) AsFabs(x Var) *Value {
	i.opcode = OpcodeFabs
	i.setArg1(x)
	i.Type = x.Type()
	return i
}

// AsFcopysign initializes this instruction as an instruction with OpcodeFcopysign.
func (i *Value) AsFcopysign(x, y Var) *Value {
	i.opcode = OpcodeFcopysign
	i.setArg2(x, y)
	i.Type = x.Type()
	return i
}

// AsCeil initializes this instruction as an instruction with OpcodeCeil.
func (i *Value) AsCeil(x Var) *Value {
	i.opcode = OpcodeCeil
	i.setArg1(x)
	i.Type = x.Type()
	return i
}

// AsFloor initializes this instruction as an instruction with OpcodeFloor.
func (i *Value) AsFloor(x Var) *Value {
	i.opcode = OpcodeFloor
	i.setArg1(x)
	i.Type = x.Type()
	return i
}

// AsTrunc initializes this instruction as an instruction with OpcodeTrunc.
func (i *Value) AsTrunc(x Var) *Value {
	i.opcode = OpcodeTrunc
	i.setArg1(x)
	i.Type = x.Type()
	return i
}

// AsNearest initializes this instruction as an instruction with OpcodeNearest.
func (i *Value) AsNearest(x Var) *Value {
	i.opcode = OpcodeNearest
	i.setArg1(x)
	i.Type = x.Type()
	return i
}

// AsBitcast initializes this instruction as an instruction with OpcodeBitcast.
func (i *Value) AsBitcast(x Var, dstType *types.Type) *Value {
	i.opcode = OpcodeBitcast
	i.setArg1(x)
	i.Type = dstType
	return i
}

// BitcastData returns the operands for a bitcast instruction.
func (i *Value) BitcastData() (x Var, dstType *types.Type) {
	return i.Args[0], i.Type
}

// AsFdemote initializes this instruction as an instruction with OpcodeFdemote.
func (i *Value) AsFdemote(x Var) {
	i.opcode = OpcodeFdemote
	i.setArg1(x)
	i.Type = types.F32
}

// AsFpromote initializes this instruction as an instruction with OpcodeFpromote.
func (i *Value) AsFpromote(x Var) {
	i.opcode = OpcodeFpromote
	i.setArg1(x)
	i.Type = types.F64
}

// AsFcvtFromInt initializes this instruction as an instruction with either OpcodeFcvtFromUint or OpcodeFcvtFromSint
func (i *Value) AsFcvtFromInt(x Var, signed bool, dst64bit bool) *Value {
	if signed {
		i.opcode = OpcodeFcvtFromSint
	} else {
		i.opcode = OpcodeFcvtFromUint
	}
	i.setArg1(x)
	if dst64bit {
		i.Type = types.F64
	} else {
		i.Type = types.F32
	}
	return i
}

// AsFcvtToInt initializes this instruction as an instruction with either OpcodeFcvtToUint or OpcodeFcvtToSint
func (i *Value) AsFcvtToInt(x, ctx Var, signed bool, dst64bit bool, sat bool) *Value {
	switch {
	case signed && !sat:
		i.opcode = OpcodeFcvtToSint
	case !signed && !sat:
		i.opcode = OpcodeFcvtToUint
	case signed && sat:
		i.opcode = OpcodeFcvtToSintSat
	case !signed && sat:
		i.opcode = OpcodeFcvtToUintSat
	}
	i.setArg2(x, ctx)
	if dst64bit {
		i.Type = types.I64
	} else {
		i.Type = types.I32
	}
	return i
}

// AsVFcvtToIntSat initializes this instruction as an instruction with either OpcodeVFcvtToSintSat or OpcodeVFcvtToUintSat
func (i *Value) AsVFcvtToIntSat(x Var, lane types.VecLane, signed bool) *Value {
	if signed {
		i.opcode = OpcodeVFcvtToSintSat
	} else {
		i.opcode = OpcodeVFcvtToUintSat
	}
	i.setArg1(x)
	i.u1 = uint64(lane)
	return i
}

// AsVFcvtFromInt initializes this instruction as an instruction with either OpcodeVFcvtToSintSat or OpcodeVFcvtToUintSat
func (i *Value) AsVFcvtFromInt(x Var, lane types.VecLane, signed bool) *Value {
	if signed {
		i.opcode = OpcodeVFcvtFromSint
	} else {
		i.opcode = OpcodeVFcvtFromUint
	}
	i.setArg1(x)
	i.u1 = uint64(lane)
	return i
}

// AsNarrow initializes this instruction as an instruction with either OpcodeSnarrow or OpcodeUnarrow
func (i *Value) AsNarrow(x, y Var, lane types.VecLane, signed bool) *Value {
	if signed {
		i.opcode = OpcodeSnarrow
	} else {
		i.opcode = OpcodeUnarrow
	}
	i.setArg2(x, y)
	i.u1 = uint64(lane)
	return i
}

// AsFvpromoteLow initializes this instruction as an instruction with OpcodeFvpromoteLow
func (i *Value) AsFvpromoteLow(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeFvpromoteLow
	i.setArg1(x)
	i.u1 = uint64(lane)
	return i
}

// AsFvdemote initializes this instruction as an instruction with OpcodeFvdemote
func (i *Value) AsFvdemote(x Var, lane types.VecLane) *Value {
	i.opcode = OpcodeFvdemote
	i.setArg1(x)
	i.u1 = uint64(lane)
	return i
}

// AsSExtend initializes this instruction as a sign extension instruction with OpcodeSExtend.
func (i *Value) AsSExtend(v Var, from, to byte) *Value {
	i.opcode = OpcodeSExtend
	i.setArg1(v)
	i.u1 = uint64(from)<<8 | uint64(to)
	if to == 64 {
		i.Type = types.I64
	} else {
		i.Type = types.I32
	}
	return i
}

// AsUExtend initializes this instruction as an unsigned extension instruction with OpcodeUExtend.
func (i *Value) AsUExtend(v Var, from, to byte) *Value {
	i.opcode = OpcodeUExtend
	i.setArg1(v)
	i.u1 = uint64(from)<<8 | uint64(to)
	if to == 64 {
		i.Type = types.I64
	} else {
		i.Type = types.I32
	}
	return i
}

func (i *Value) ExtendData() (from, to byte, signed bool) {
	if i.opcode != OpcodeSExtend && i.opcode != OpcodeUExtend {
		panic("BUG: ExtendData only available for OpcodeSExtend and OpcodeUExtend")
	}
	from = byte(i.u1 >> 8)
	to = byte(i.u1)
	signed = i.opcode == OpcodeSExtend
	return
}

// AsSelect initializes this instruction as an unsigned extension instruction with OpcodeSelect.
func (i *Value) AsSelect(c, x, y Var) *Value {
	i.opcode = OpcodeSelect
	i.setArg3(c, x, y)
	i.Type = x.Type()
	return i
}

// SelectData returns the select data for this instruction necessary for backends.
func (i *Value) SelectData() (c, x, y Var) {
	c = i.Args[0]
	x = i.Args[1]
	y = i.Args[2]
	return
}

// ExtendFromToBits returns the from and to bit size for the extension instruction.
func (i *Value) ExtendFromToBits() (from, to byte) {
	from = byte(i.u1 >> 8)
	to = byte(i.u1)
	return
}

// Format returns a string representation of this instruction with the given builder.
// For debugging purposes only.
func (i *Value) Format(b *Builder) string {
	var instSuffix string
	switch i.opcode {
	case OpcodeExitWithCode:
		instSuffix = fmt.Sprintf(" %s, %s", i.Args[0].Format(b), wazevoapi.ExitCode(i.u1))
	case OpcodeExitIfTrueWithCode:
		instSuffix = fmt.Sprintf(" %s, %s, %s", i.Args[1].Format(b), i.Args[0].Format(b), wazevoapi.ExitCode(i.u1))
	case OpcodeIadd, OpcodeIsub, OpcodeImul, OpcodeFadd, OpcodeFsub, OpcodeFmin, OpcodeFmax, OpcodeFdiv, OpcodeFmul:
		instSuffix = fmt.Sprintf(" %s, %s", i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeIcmp:
		instSuffix = fmt.Sprintf(" %s, %s, %s", IntegerCmpCond(i.u1), i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeFcmp:
		instSuffix = fmt.Sprintf(" %s, %s, %s", FloatCmpCond(i.u1), i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeSExtend, OpcodeUExtend:
		instSuffix = fmt.Sprintf(" %s, %d->%d", i.Args[0].Format(b), i.u1>>8, i.u1&0xff)
	case OpcodeCall, OpcodeCallIndirect:
		view := i.Args
		if i.opcode == OpcodeCallIndirect {
			view = i.Args[1:]
		}
		vs := make([]string, len(view))
		for idx := range vs {
			vs[idx] = view[idx].Format(b)
		}
		if i.opcode == OpcodeCallIndirect {
			instSuffix = fmt.Sprintf(" %s:%s, %s", i.Args[0].Format(b), types.SignatureID(i.u1), strings.Join(vs, ", "))
		} else {
			instSuffix = fmt.Sprintf(" %s:%s, %s", FuncRef(i.u1), types.SignatureID(i.u2), strings.Join(vs, ", "))
		}
	case OpcodeStore, OpcodeIstore8, OpcodeIstore16, OpcodeIstore32:
		instSuffix = fmt.Sprintf(" %s, %s, %#x", i.Args[0].Format(b), i.Args[1].Format(b), uint32(i.u1))
	case OpcodeLoad, OpcodeVZeroExtLoad:
		instSuffix = fmt.Sprintf(" %s, %#x", i.Args[0].Format(b), int32(i.u1))
	case OpcodeLoadSplat:
		instSuffix = fmt.Sprintf(".%s %s, %#x", types.VecLane(i.u2), i.Args[0].Format(b), int32(i.u1))
	case OpcodeUload8, OpcodeUload16, OpcodeUload32, OpcodeSload8, OpcodeSload16, OpcodeSload32:
		instSuffix = fmt.Sprintf(" %s, %#x", i.Args[0].Format(b), int32(i.u1))
	case OpcodeSelect, OpcodeVbitselect:
		instSuffix = fmt.Sprintf(" %s, %s, %s", i.Args[0].Format(b), i.Args[1].Format(b), i.Args[2].Format(b))
	case OpcodeIconst:
		switch i.Type {
		case types.I32:
			instSuffix = fmt.Sprintf("_32 %#x", uint32(i.u1))
		case types.I64:
			instSuffix = fmt.Sprintf("_64 %#x", i.u1)
		}
	case OpcodeVconst:
		instSuffix = fmt.Sprintf(" %016x %016x", i.u1, i.u2)
	case OpcodeF32const:
		instSuffix = fmt.Sprintf(" %f", math.Float32frombits(uint32(i.u1)))
	case OpcodeF64const:
		instSuffix = fmt.Sprintf(" %f", math.Float64frombits(i.u1))
	case OpcodeReturn:
		view := i.Args
		if len(view) == 0 {
			break
		}
		vs := make([]string, len(view))
		for idx := range vs {
			vs[idx] = view[idx].Format(b)
		}
		instSuffix = fmt.Sprintf(" %s", strings.Join(vs, ", "))
	case OpcodeBand, OpcodeBor, OpcodeBxor, OpcodeRotr, OpcodeRotl, OpcodeIshl, OpcodeSshr, OpcodeUshr,
		OpcodeSdiv, OpcodeUdiv, OpcodeFcopysign, OpcodeSrem, OpcodeUrem,
		OpcodeVbnot, OpcodeVbxor, OpcodeVbor, OpcodeVband, OpcodeVbandnot, OpcodeVIcmp, OpcodeVFcmp:
		instSuffix = fmt.Sprintf(" %s, %s", i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeUndefined:
	case OpcodeClz, OpcodeCtz, OpcodePopcnt, OpcodeFneg, OpcodeFcvtToSint, OpcodeFcvtToUint, OpcodeFcvtFromSint,
		OpcodeFcvtFromUint, OpcodeFcvtToSintSat, OpcodeFcvtToUintSat, OpcodeFdemote, OpcodeFpromote, OpcodeIreduce, OpcodeBitcast, OpcodeSqrt, OpcodeFabs,
		OpcodeCeil, OpcodeFloor, OpcodeTrunc, OpcodeNearest:
		instSuffix = " " + i.Args[0].Format(b)
	case OpcodeVIadd, OpcodeExtIaddPairwise, OpcodeVSaddSat, OpcodeVUaddSat, OpcodeVIsub, OpcodeVSsubSat, OpcodeVUsubSat,
		OpcodeVImin, OpcodeVUmin, OpcodeVImax, OpcodeVUmax, OpcodeVImul, OpcodeVAvgRound,
		OpcodeVFadd, OpcodeVFsub, OpcodeVFmul, OpcodeVFdiv,
		OpcodeVIshl, OpcodeVSshr, OpcodeVUshr,
		OpcodeVFmin, OpcodeVFmax, OpcodeVMinPseudo, OpcodeVMaxPseudo,
		OpcodeSnarrow, OpcodeUnarrow, OpcodeSwizzle, OpcodeSqmulRoundSat:
		instSuffix = fmt.Sprintf(".%s %s, %s", types.VecLane(i.u1), i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeVIabs, OpcodeVIneg, OpcodeVIpopcnt, OpcodeVhighBits, OpcodeVallTrue, OpcodeVanyTrue,
		OpcodeVFabs, OpcodeVFneg, OpcodeVSqrt, OpcodeVCeil, OpcodeVFloor, OpcodeVTrunc, OpcodeVNearest,
		OpcodeVFcvtToUintSat, OpcodeVFcvtToSintSat, OpcodeVFcvtFromUint, OpcodeVFcvtFromSint,
		OpcodeFvpromoteLow, OpcodeFvdemote, OpcodeSwidenLow, OpcodeUwidenLow, OpcodeSwidenHigh, OpcodeUwidenHigh,
		OpcodeSplat:
		instSuffix = fmt.Sprintf(".%s %s", types.VecLane(i.u1), i.Args[0].Format(b))
	case OpcodeExtractlane:
		var signedness string
		if i.u1 != 0 {
			signedness = "signed"
		} else {
			signedness = "unsigned"
		}
		instSuffix = fmt.Sprintf(".%s %d, %s (%s)", types.VecLane(i.u2), 0x0000FFFF&i.u1, i.Args[0].Format(b), signedness)
	case OpcodeInsertlane:
		instSuffix = fmt.Sprintf(".%s %d, %s, %s", types.VecLane(i.u2), i.u1, i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeShuffle:
		lanes := make([]byte, 16)
		for idx := 0; idx < 8; idx++ {
			lanes[idx] = byte(i.u1 >> (8 * idx))
		}
		for idx := 0; idx < 8; idx++ {
			lanes[idx+8] = byte(i.u2 >> (8 * idx))
		}
		// Prints Shuffle.[0 1 2 3 4 5 6 7 ...] v2, v3
		instSuffix = fmt.Sprintf(".%v %s, %s", lanes, i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeAtomicRmw:
		instSuffix = fmt.Sprintf(" %s_%d, %s, %s", AtomicRmwOp(i.u1), 8*i.u2, i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeAtomicLoad:
		instSuffix = fmt.Sprintf("_%d, %s", 8*i.u1, i.Args[0].Format(b))
	case OpcodeAtomicStore:
		instSuffix = fmt.Sprintf("_%d, %s, %s", 8*i.u1, i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeAtomicCas:
		instSuffix = fmt.Sprintf("_%d, %s, %s, %s", 8*i.u1, i.Args[0].Format(b), i.Args[1].Format(b), i.Args[2].Format(b))
	case OpcodeFence:
		instSuffix = fmt.Sprintf(" %d", i.u1)
	case OpcodeTailCallReturnCall, OpcodeTailCallReturnCallIndirect:
		view := i.Args
		if i.opcode == OpcodeTailCallReturnCallIndirect {
			view = i.Args[1:]
		}
		vs := make([]string, len(view))
		for idx := range vs {
			vs[idx] = view[idx].Format(b)
		}
		if i.opcode == OpcodeCallIndirect {
			instSuffix = fmt.Sprintf(" %s:%s, %s", i.Args[0].Format(b), types.SignatureID(i.u1), strings.Join(vs, ", "))
		} else {
			instSuffix = fmt.Sprintf(" %s:%s, %s", FuncRef(i.u1), types.SignatureID(i.u2), strings.Join(vs, ", "))
		}
	case OpcodeWideningPairwiseDotProductS:
		instSuffix = fmt.Sprintf(" %s, %s", i.Args[0].Format(b), i.Args[1].Format(b))
	case OpcodeSelectTuple:
		instSuffix = fmt.Sprintf(" %s, %d", i.Args[0].Format(b), i.u1)
	default:
		panic(fmt.Sprintf("TODO: format for %s", i.opcode))
	}

	instr := i.opcode.String() + instSuffix
	if i.Return.Valid() {
		return fmt.Sprintf("%s = %s", i.Return.formatWithType(b), instr)
	} else {
		return instr
	}
}

// Constant returns true if this instruction is a constant instruction.
func (i *Value) Constant() bool {
	switch i.opcode {
	case OpcodeIconst, OpcodeF32const, OpcodeF64const:
		return true
	}
	return false
}

// ConstantVal returns the constant value of this instruction.
// How to interpret the return value depends on the opcode.
func (i *Value) ConstantVal() (ret uint64) {
	switch i.opcode {
	case OpcodeIconst, OpcodeF32const, OpcodeF64const:
		ret = i.u1
	default:
		panic("TODO")
	}
	return
}

// String implements fmt.Stringer.
func (o Opcode) String() (ret string) {
	switch o {
	case OpcodeInvalid:
		return "invalid"
	case OpcodeUndefined:
		return "Undefined"
	case OpcodeExitWithCode:
		return "Exit"
	case OpcodeExitIfTrueWithCode:
		return "ExitIfTrue"
	case OpcodeReturn:
		return "Return"
	case OpcodeCall:
		return "Call"
	case OpcodeCallIndirect:
		return "CallIndirect"
	case OpcodeSplat:
		return "Splat"
	case OpcodeSwizzle:
		return "Swizzle"
	case OpcodeInsertlane:
		return "Insertlane"
	case OpcodeExtractlane:
		return "Extractlane"
	case OpcodeLoad:
		return "Load"
	case OpcodeLoadSplat:
		return "LoadSplat"
	case OpcodeStore:
		return "Store"
	case OpcodeUload8:
		return "Uload8"
	case OpcodeSload8:
		return "Sload8"
	case OpcodeIstore8:
		return "Istore8"
	case OpcodeUload16:
		return "Uload16"
	case OpcodeSload16:
		return "Sload16"
	case OpcodeIstore16:
		return "Istore16"
	case OpcodeUload32:
		return "Uload32"
	case OpcodeSload32:
		return "Sload32"
	case OpcodeIstore32:
		return "Istore32"
	case OpcodeIconst:
		return "Iconst"
	case OpcodeF32const:
		return "F32const"
	case OpcodeF64const:
		return "F64const"
	case OpcodeVconst:
		return "Vconst"
	case OpcodeShuffle:
		return "Shuffle"
	case OpcodeSelect:
		return "Select"
	case OpcodeVanyTrue:
		return "VanyTrue"
	case OpcodeVallTrue:
		return "VallTrue"
	case OpcodeVhighBits:
		return "VhighBits"
	case OpcodeIcmp:
		return "Icmp"
	case OpcodeIcmpImm:
		return "IcmpImm"
	case OpcodeVIcmp:
		return "VIcmp"
	case OpcodeIadd:
		return "Iadd"
	case OpcodeIsub:
		return "Isub"
	case OpcodeImul:
		return "Imul"
	case OpcodeUdiv:
		return "Udiv"
	case OpcodeSdiv:
		return "Sdiv"
	case OpcodeUrem:
		return "Urem"
	case OpcodeSrem:
		return "Srem"
	case OpcodeBand:
		return "Band"
	case OpcodeBor:
		return "Bor"
	case OpcodeBxor:
		return "Bxor"
	case OpcodeBnot:
		return "Bnot"
	case OpcodeRotl:
		return "Rotl"
	case OpcodeRotr:
		return "Rotr"
	case OpcodeIshl:
		return "Ishl"
	case OpcodeUshr:
		return "Ushr"
	case OpcodeSshr:
		return "Sshr"
	case OpcodeClz:
		return "Clz"
	case OpcodeCtz:
		return "Ctz"
	case OpcodePopcnt:
		return "Popcnt"
	case OpcodeFcmp:
		return "Fcmp"
	case OpcodeFadd:
		return "Fadd"
	case OpcodeFsub:
		return "Fsub"
	case OpcodeFmul:
		return "Fmul"
	case OpcodeFdiv:
		return "Fdiv"
	case OpcodeSqmulRoundSat:
		return "SqmulRoundSat"
	case OpcodeSqrt:
		return "Sqrt"
	case OpcodeFneg:
		return "Fneg"
	case OpcodeFabs:
		return "Fabs"
	case OpcodeFcopysign:
		return "Fcopysign"
	case OpcodeFmin:
		return "Fmin"
	case OpcodeFmax:
		return "Fmax"
	case OpcodeCeil:
		return "Ceil"
	case OpcodeFloor:
		return "Floor"
	case OpcodeTrunc:
		return "Trunc"
	case OpcodeNearest:
		return "Nearest"
	case OpcodeBitcast:
		return "Bitcast"
	case OpcodeIreduce:
		return "Ireduce"
	case OpcodeSnarrow:
		return "Snarrow"
	case OpcodeUnarrow:
		return "Unarrow"
	case OpcodeSwidenLow:
		return "SwidenLow"
	case OpcodeSwidenHigh:
		return "SwidenHigh"
	case OpcodeUwidenLow:
		return "UwidenLow"
	case OpcodeUwidenHigh:
		return "UwidenHigh"
	case OpcodeExtIaddPairwise:
		return "IaddPairwise"
	case OpcodeWideningPairwiseDotProductS:
		return "WideningPairwiseDotProductS"
	case OpcodeUExtend:
		return "UExtend"
	case OpcodeSExtend:
		return "SExtend"
	case OpcodeFpromote:
		return "Fpromote"
	case OpcodeFdemote:
		return "Fdemote"
	case OpcodeFvdemote:
		return "Fvdemote"
	case OpcodeFcvtToUint:
		return "FcvtToUint"
	case OpcodeFcvtToSint:
		return "FcvtToSint"
	case OpcodeFcvtToUintSat:
		return "FcvtToUintSat"
	case OpcodeFcvtToSintSat:
		return "FcvtToSintSat"
	case OpcodeFcvtFromUint:
		return "FcvtFromUint"
	case OpcodeFcvtFromSint:
		return "FcvtFromSint"
	case OpcodeAtomicRmw:
		return "AtomicRmw"
	case OpcodeAtomicCas:
		return "AtomicCas"
	case OpcodeAtomicLoad:
		return "AtomicLoad"
	case OpcodeAtomicStore:
		return "AtomicStore"
	case OpcodeFence:
		return "Fence"
	case OpcodeTailCallReturnCall:
		return "ReturnCall"
	case OpcodeTailCallReturnCallIndirect:
		return "ReturnCallIndirect"
	case OpcodeVbor:
		return "Vbor"
	case OpcodeVbxor:
		return "Vbxor"
	case OpcodeVband:
		return "Vband"
	case OpcodeVbandnot:
		return "Vbandnot"
	case OpcodeVbnot:
		return "Vbnot"
	case OpcodeVbitselect:
		return "Vbitselect"
	case OpcodeVIadd:
		return "VIadd"
	case OpcodeVSaddSat:
		return "VSaddSat"
	case OpcodeVUaddSat:
		return "VUaddSat"
	case OpcodeVSsubSat:
		return "VSsubSat"
	case OpcodeVUsubSat:
		return "VUsubSat"
	case OpcodeVAvgRound:
		return "OpcodeVAvgRound"
	case OpcodeVIsub:
		return "VIsub"
	case OpcodeVImin:
		return "VImin"
	case OpcodeVUmin:
		return "VUmin"
	case OpcodeVImax:
		return "VImax"
	case OpcodeVUmax:
		return "VUmax"
	case OpcodeVImul:
		return "VImul"
	case OpcodeVIabs:
		return "VIabs"
	case OpcodeVIneg:
		return "VIneg"
	case OpcodeVIpopcnt:
		return "VIpopcnt"
	case OpcodeVIshl:
		return "VIshl"
	case OpcodeVUshr:
		return "VUshr"
	case OpcodeVSshr:
		return "VSshr"
	case OpcodeVFabs:
		return "VFabs"
	case OpcodeVFmax:
		return "VFmax"
	case OpcodeVFmin:
		return "VFmin"
	case OpcodeVFneg:
		return "VFneg"
	case OpcodeVFadd:
		return "VFadd"
	case OpcodeVFsub:
		return "VFsub"
	case OpcodeVFmul:
		return "VFmul"
	case OpcodeVFdiv:
		return "VFdiv"
	case OpcodeVFcmp:
		return "VFcmp"
	case OpcodeVCeil:
		return "VCeil"
	case OpcodeVFloor:
		return "VFloor"
	case OpcodeVTrunc:
		return "VTrunc"
	case OpcodeVNearest:
		return "VNearest"
	case OpcodeVMaxPseudo:
		return "VMaxPseudo"
	case OpcodeVMinPseudo:
		return "VMinPseudo"
	case OpcodeVSqrt:
		return "VSqrt"
	case OpcodeVFcvtToUintSat:
		return "VFcvtToUintSat"
	case OpcodeVFcvtToSintSat:
		return "VFcvtToSintSat"
	case OpcodeVFcvtFromUint:
		return "VFcvtFromUint"
	case OpcodeVFcvtFromSint:
		return "VFcvtFromSint"
	case OpcodeFvpromoteLow:
		return "FvpromoteLow"
	case OpcodeVZeroExtLoad:
		return "VZeroExtLoad"
	case OpcodeSelectTuple:
		return "SelectTuple"
	}
	panic(fmt.Sprintf("unknown opcode %d", o))
}
