package ssa

import "github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"

// TODO: complete opcode comments.
const (
	OpcodeInvalid Opcode = iota

	// OpcodeUndefined is a placeholder for undefined opcode. This can be used for debugging to intentionally
	// cause a crash at certain point.
	OpcodeUndefined

	// OpcodeExitWithCode exit the execution immediately.
	OpcodeExitWithCode

	// OpcodeExitIfTrueWithCode exits the execution immediately if the value `c` is not zero.
	OpcodeExitIfTrueWithCode

	// OpcodeReturn returns from the function: `return rvalues`.
	OpcodeReturn

	// OpcodeCall calls a function specified by the symbol FN with arguments `args`: `returnvals = Call FN, args...`
	// This is a "near" call, which means the call target is known at compile time, and the target is relatively close
	// to this function. If the target cannot be reached by near call, the backend fails to compile.
	OpcodeCall

	// OpcodeCallIndirect calls a function specified by `callee` which is a function address: `returnvals = call_indirect SIG, callee, args`.
	// Note that this is different from call_indirect in Wasm, which also does type checking, etc.
	OpcodeCallIndirect

	// OpcodeSplat performs a vector splat operation: `v = Splat.lane x`.
	OpcodeSplat

	// OpcodeSwizzle performs a vector swizzle operation: `v = Swizzle.lane x, y`.
	OpcodeSwizzle

	// OpcodeInsertlane inserts a lane value into a vector: `v = InsertLane x, y, Idx`.
	OpcodeInsertlane

	// OpcodeExtractlane extracts a lane value from a vector: `v = ExtractLane x, Idx`.
	OpcodeExtractlane

	// OpcodeLoad loads a *types.Type value from the [base + offset] address: `v = Load base, offset`.
	OpcodeLoad

	// OpcodeStore stores a *types.Type value to the [base + offset] address: `Store v, base, offset`.
	OpcodeStore

	// OpcodeUload8 loads the 8-bit value from the [base + offset] address, zero-extended to 64 bits: `v = Uload8 base, offset`.
	OpcodeUload8

	// OpcodeSload8 loads the 8-bit value from the [base + offset] address, sign-extended to 64 bits: `v = Sload8 base, offset`.
	OpcodeSload8

	// OpcodeIstore8 stores the 8-bit value to the [base + offset] address, sign-extended to 64 bits: `Istore8 v, base, offset`.
	OpcodeIstore8

	// OpcodeUload16 loads the 16-bit value from the [base + offset] address, zero-extended to 64 bits: `v = Uload16 base, offset`.
	OpcodeUload16

	// OpcodeSload16 loads the 16-bit value from the [base + offset] address, sign-extended to 64 bits: `v = Sload16 base, offset`.
	OpcodeSload16

	// OpcodeIstore16 stores the 16-bit value to the [base + offset] address, zero-extended to 64 bits: `Istore16 v, base, offset`.
	OpcodeIstore16

	// OpcodeUload32 loads the 32-bit value from the [base + offset] address, zero-extended to 64 bits: `v = Uload32 base, offset`.
	OpcodeUload32

	// OpcodeSload32 loads the 32-bit value from the [base + offset] address, sign-extended to 64 bits: `v = Sload32 base, offset`.
	OpcodeSload32

	// OpcodeIstore32 stores the 32-bit value to the [base + offset] address, zero-extended to 64 bits: `Istore16 v, base, offset`.
	OpcodeIstore32

	// OpcodeLoadSplat represents a load that replicates the loaded value to all lanes `v = LoadSplat.lane p, Offset`.
	OpcodeLoadSplat

	// OpcodeVZeroExtLoad loads a scalar single/double precision floating point value from the [p + Offset] address,
	// and zero-extend it to the V128 value: `v = VExtLoad  p, Offset`.
	OpcodeVZeroExtLoad

	// OpcodeIconst represents the integer const.
	OpcodeIconst

	// OpcodeF32const represents the single-precision const.
	OpcodeF32const

	// OpcodeF64const represents the double-precision const.
	OpcodeF64const

	// OpcodeVconst represents the 128bit vector const.
	OpcodeVconst

	// OpcodeVbor computes binary or between two 128bit vectors: `v = bor x, y`.
	OpcodeVbor

	// OpcodeVbxor computes binary xor between two 128bit vectors: `v = bxor x, y`.
	OpcodeVbxor

	// OpcodeVband computes binary and between two 128bit vectors: `v = band x, y`.
	OpcodeVband

	// OpcodeVbandnot computes binary and-not between two 128bit vectors: `v = bandnot x, y`.
	OpcodeVbandnot

	// OpcodeVbnot negates a 128bit vector: `v = bnot x`.
	OpcodeVbnot

	// OpcodeVbitselect uses the bits in the control mask c to select the corresponding bit from x when 1
	// and y when 0: `v = bitselect c, x, y`.
	OpcodeVbitselect

	// OpcodeShuffle shuffles two vectors using the given 128-bit immediate: `v = shuffle imm, x, y`.
	// For each byte in the immediate, a value i in [0, 15] selects the i-th byte in vector x;
	// i in [16, 31] selects the (i-16)-th byte in vector y.
	OpcodeShuffle

	// OpcodeSelect chooses between two values based on a condition `c`: `v = Select c, x, y`.
	OpcodeSelect

	// OpcodeVanyTrue performs a any true operation: `s = VanyTrue a`.
	OpcodeVanyTrue

	// OpcodeVallTrue performs a lane-wise all true operation: `s = VallTrue.lane a`.
	OpcodeVallTrue

	// OpcodeVhighBits performs a lane-wise extract of the high bits: `v = VhighBits.lane a`.
	OpcodeVhighBits

	// OpcodeIcmp compares two integer values with the given condition: `v = icmp Cond, x, y`.
	OpcodeIcmp

	// OpcodeVIcmp compares two integer values with the given condition: `v = vicmp Cond, x, y` on vector.
	OpcodeVIcmp

	// OpcodeIcmpImm compares an integer value with the immediate value on the given condition: `v = icmp_imm Cond, x, Y`.
	OpcodeIcmpImm

	// OpcodeIadd performs an integer addition: `v = Iadd x, y`.
	OpcodeIadd

	// OpcodeVIadd performs an integer addition: `v = VIadd.lane x, y` on vector.
	OpcodeVIadd

	// OpcodeVSaddSat performs a signed saturating vector addition: `v = VSaddSat.lane x, y` on vector.
	OpcodeVSaddSat

	// OpcodeVUaddSat performs an unsigned saturating vector addition: `v = VUaddSat.lane x, y` on vector.
	OpcodeVUaddSat

	// OpcodeIsub performs an integer subtraction: `v = Isub x, y`.
	OpcodeIsub

	// OpcodeVIsub performs an integer subtraction: `v = VIsub.lane x, y` on vector.
	OpcodeVIsub

	// OpcodeVSsubSat performs a signed saturating vector subtraction: `v = VSsubSat.lane x, y` on vector.
	OpcodeVSsubSat

	// OpcodeVUsubSat performs an unsigned saturating vector subtraction: `v = VUsubSat.lane x, y` on vector.
	OpcodeVUsubSat

	// OpcodeVImin performs a signed integer min: `v = VImin.lane x, y` on vector.
	OpcodeVImin

	// OpcodeVUmin performs an unsigned integer min: `v = VUmin.lane x, y` on vector.
	OpcodeVUmin

	// OpcodeVImax performs a signed integer max: `v = VImax.lane x, y` on vector.
	OpcodeVImax

	// OpcodeVUmax performs an unsigned integer max: `v = VUmax.lane x, y` on vector.
	OpcodeVUmax

	// OpcodeVAvgRound performs an unsigned integer avg, truncating to zero: `v = VAvgRound.lane x, y` on vector.
	OpcodeVAvgRound

	// OpcodeVImul performs an integer multiplication: `v = VImul.lane x, y` on vector.
	OpcodeVImul

	// OpcodeVIneg negates the given integer vector value: `v = VIneg x`.
	OpcodeVIneg

	// OpcodeVIpopcnt counts the number of 1-bits in the given vector: `v = VIpopcnt x`.
	OpcodeVIpopcnt

	// OpcodeVIabs returns the absolute value for the given vector value: `v = VIabs.lane x`.
	OpcodeVIabs

	// OpcodeVIshl shifts x left by (y mod lane-width): `v = VIshl.lane x, y` on vector.
	OpcodeVIshl

	// OpcodeVUshr shifts x right by (y mod lane-width), unsigned: `v = VUshr.lane x, y` on vector.
	OpcodeVUshr

	// OpcodeVSshr shifts x right by (y mod lane-width), signed: `v = VSshr.lane x, y` on vector.
	OpcodeVSshr

	// OpcodeVFabs takes the absolute value of a floating point value: `v = VFabs.lane x on vector.
	OpcodeVFabs

	// OpcodeVFmax takes the maximum of two floating point values: `v = VFmax.lane x, y on vector.
	OpcodeVFmax

	// OpcodeVFmin takes the minimum of two floating point values: `v = VFmin.lane x, y on vector.
	OpcodeVFmin

	// OpcodeVFneg negates the given floating point vector value: `v = VFneg x`.
	OpcodeVFneg

	// OpcodeVFadd performs a floating point addition: `v = VFadd.lane x, y` on vector.
	OpcodeVFadd

	// OpcodeVFsub performs a floating point subtraction: `v = VFsub.lane x, y` on vector.
	OpcodeVFsub

	// OpcodeVFmul performs a floating point multiplication: `v = VFmul.lane x, y` on vector.
	OpcodeVFmul

	// OpcodeVFdiv performs a floating point division: `v = VFdiv.lane x, y` on vector.
	OpcodeVFdiv

	// OpcodeVFcmp compares two float values with the given condition: `v = VFcmp.lane Cond, x, y` on float.
	OpcodeVFcmp

	// OpcodeVCeil takes the ceiling of the given floating point value: `v = ceil.lane x` on vector.
	OpcodeVCeil

	// OpcodeVFloor takes the floor of the given floating point value: `v = floor.lane x` on vector.
	OpcodeVFloor

	// OpcodeVTrunc takes the truncation of the given floating point value: `v = trunc.lane x` on vector.
	OpcodeVTrunc

	// OpcodeVNearest takes the nearest integer of the given floating point value: `v = nearest.lane x` on vector.
	OpcodeVNearest

	// OpcodeVMaxPseudo computes the lane-wise maximum value `v = VMaxPseudo.lane x, y` on vector defined as `x < y ? x : y`.
	OpcodeVMaxPseudo

	// OpcodeVMinPseudo computes the lane-wise minimum value `v = VMinPseudo.lane x, y` on vector defined as `y < x ? x : y`.
	OpcodeVMinPseudo

	// OpcodeVSqrt takes the minimum of two floating point values: `v = VFmin.lane x, y` on vector.
	OpcodeVSqrt

	// OpcodeVFcvtToUintSat converts a floating point value to an unsigned integer: `v = FcvtToUintSat.lane x` on vector.
	OpcodeVFcvtToUintSat

	// OpcodeVFcvtToSintSat converts a floating point value to a signed integer: `v = VFcvtToSintSat.lane x` on vector.
	OpcodeVFcvtToSintSat

	// OpcodeVFcvtFromUint converts a floating point value from an unsigned integer: `v = FcvtFromUint.lane x` on vector.
	// x is always a 32-bit integer lane, and the result is either a 32-bit or 64-bit floating point-sized vector.
	OpcodeVFcvtFromUint

	// OpcodeVFcvtFromSint converts a floating point value from a signed integer: `v = VFcvtFromSint.lane x` on vector.
	// x is always a 32-bit integer lane, and the result is either a 32-bit or 64-bit floating point-sized vector.
	OpcodeVFcvtFromSint

	// OpcodeImul performs an integer multiplication: `v = Imul x, y`.
	OpcodeImul

	// OpcodeUdiv performs the unsigned integer division `v = Udiv x, y`.
	OpcodeUdiv

	// OpcodeSdiv performs the signed integer division `v = Sdiv x, y`.
	OpcodeSdiv

	// OpcodeUrem computes the remainder of the unsigned integer division `v = Urem x, y`.
	OpcodeUrem

	// OpcodeSrem computes the remainder of the signed integer division `v = Srem x, y`.
	OpcodeSrem

	// OpcodeBand performs a binary and: `v = Band x, y`.
	OpcodeBand

	// OpcodeBor performs a binary or: `v = Bor x, y`.
	OpcodeBor

	// OpcodeBxor performs a binary xor: `v = Bxor x, y`.
	OpcodeBxor

	// OpcodeBnot performs a binary not: `v = Bnot x`.
	OpcodeBnot

	// OpcodeRotl rotates the given integer value to the left: `v = Rotl x, y`.
	OpcodeRotl

	// OpcodeRotr rotates the given integer value to the right: `v = Rotr x, y`.
	OpcodeRotr

	// OpcodeIshl does logical shift left: `v = Ishl x, y`.
	OpcodeIshl

	// OpcodeUshr does logical shift right: `v = Ushr x, y`.
	OpcodeUshr

	// OpcodeSshr does arithmetic shift right: `v = Sshr x, y`.
	OpcodeSshr

	// OpcodeClz counts the number of leading zeros: `v = clz x`.
	OpcodeClz

	// OpcodeCtz counts the number of trailing zeros: `v = ctz x`.
	OpcodeCtz

	// OpcodePopcnt counts the number of 1-bits: `v = popcnt x`.
	OpcodePopcnt

	// OpcodeFcmp compares two floating point values: `v = fcmp Cond, x, y`.
	OpcodeFcmp

	// OpcodeFadd performs a floating point addition: / `v = Fadd x, y`.
	OpcodeFadd

	// OpcodeFsub performs a floating point subtraction: `v = Fsub x, y`.
	OpcodeFsub

	// OpcodeFmul performs a floating point multiplication: `v = Fmul x, y`.
	OpcodeFmul

	// OpcodeSqmulRoundSat performs a lane-wise saturating rounding multiplication
	// in Q15 format: `v = SqmulRoundSat.lane x,y` on vector.
	OpcodeSqmulRoundSat

	// OpcodeFdiv performs a floating point division: `v = Fdiv x, y`.
	OpcodeFdiv

	// OpcodeSqrt takes the square root of the given floating point value: `v = sqrt x`.
	OpcodeSqrt

	// OpcodeFneg negates the given floating point value: `v = Fneg x`.
	OpcodeFneg

	// OpcodeFabs takes the absolute value of the given floating point value: `v = fabs x`.
	OpcodeFabs

	// OpcodeFcopysign copies the sign of the second floating point value to the first floating point value:
	// `v = Fcopysign x, y`.
	OpcodeFcopysign

	// OpcodeFmin takes the minimum of two floating point values: `v = fmin x, y`.
	OpcodeFmin

	// OpcodeFmax takes the maximum of two floating point values: `v = fmax x, y`.
	OpcodeFmax

	// OpcodeCeil takes the ceiling of the given floating point value: `v = ceil x`.
	OpcodeCeil

	// OpcodeFloor takes the floor of the given floating point value: `v = floor x`.
	OpcodeFloor

	// OpcodeTrunc takes the truncation of the given floating point value: `v = trunc x`.
	OpcodeTrunc

	// OpcodeNearest takes the nearest integer of the given floating point value: `v = nearest x`.
	OpcodeNearest

	// OpcodeBitcast is a bitcast operation: `v = bitcast x`.
	OpcodeBitcast

	// OpcodeIreduce narrow the given integer: `v = Ireduce x`.
	OpcodeIreduce

	// OpcodeSnarrow converts two input vectors x, y into a smaller lane vector by narrowing each lane, signed `v = Snarrow.lane x, y`.
	OpcodeSnarrow

	// OpcodeUnarrow converts two input vectors x, y into a smaller lane vector by narrowing each lane, unsigned `v = Unarrow.lane x, y`.
	OpcodeUnarrow

	// OpcodeSwidenLow converts low half of the smaller lane vector to a larger lane vector, sign extended: `v = SwidenLow.lane x`.
	OpcodeSwidenLow

	// OpcodeSwidenHigh converts high half of the smaller lane vector to a larger lane vector, sign extended: `v = SwidenHigh.lane x`.
	OpcodeSwidenHigh

	// OpcodeUwidenLow converts low half of the smaller lane vector to a larger lane vector, zero (unsigned) extended: `v = UwidenLow.lane x`.
	OpcodeUwidenLow

	// OpcodeUwidenHigh converts high half of the smaller lane vector to a larger lane vector, zero (unsigned) extended: `v = UwidenHigh.lane x`.
	OpcodeUwidenHigh

	// OpcodeExtIaddPairwise is a lane-wise integer extended pairwise addition producing extended results (twice wider results than the inputs): `v = extiadd_pairwise x, y` on vector.
	OpcodeExtIaddPairwise

	// OpcodeWideningPairwiseDotProductS is a lane-wise widening pairwise dot product with signed saturation: `v = WideningPairwiseDotProductS x, y` on vector.
	// Currently, the only lane is i16, and the result is i32.
	OpcodeWideningPairwiseDotProductS

	// OpcodeUExtend zero-extends the given integer: `v = UExtend x, from->to`.
	OpcodeUExtend

	// OpcodeSExtend sign-extends the given integer: `v = SExtend x, from->to`.
	OpcodeSExtend

	// OpcodeFpromote promotes the given floating point value: `v = Fpromote x`.
	OpcodeFpromote

	// OpcodeFvpromoteLow converts the two lower single-precision floating point lanes
	// to the two double-precision lanes of the result: `v = FvpromoteLow.lane x` on vector.
	OpcodeFvpromoteLow

	// OpcodeFdemote demotes the given float point value: `v = Fdemote x`.
	OpcodeFdemote

	// OpcodeFvdemote converts the two double-precision floating point lanes
	// to two lower single-precision lanes of the result `v = Fvdemote.lane x`.
	OpcodeFvdemote

	// OpcodeFcvtToUint converts a floating point value to an unsigned integer: `v = FcvtToUint x`.
	OpcodeFcvtToUint

	// OpcodeFcvtToSint converts a floating point value to a signed integer: `v = FcvtToSint x`.
	OpcodeFcvtToSint

	// OpcodeFcvtToUintSat converts a floating point value to an unsigned integer: `v = FcvtToUintSat x` which saturates on overflow.
	OpcodeFcvtToUintSat

	// OpcodeFcvtToSintSat converts a floating point value to a signed integer: `v = FcvtToSintSat x` which saturates on overflow.
	OpcodeFcvtToSintSat

	// OpcodeFcvtFromUint converts an unsigned integer to a floating point value: `v = FcvtFromUint x`.
	OpcodeFcvtFromUint

	// OpcodeFcvtFromSint converts a signed integer to a floating point value: `v = FcvtFromSint x`.
	OpcodeFcvtFromSint

	// OpcodeAtomicRmw is atomic read-modify-write operation: `v = atomic_rmw op, p, offset, value`.
	OpcodeAtomicRmw

	// OpcodeAtomicCas is atomic compare-and-swap operation.
	OpcodeAtomicCas

	// OpcodeAtomicLoad is atomic load operation.
	OpcodeAtomicLoad

	// OpcodeAtomicStore is atomic store operation.
	OpcodeAtomicStore

	// OpcodeFence is a memory fence operation.
	OpcodeFence

	// OpcodeTailCallReturnCall is the equivalent of OpcodeCall (a "near" call)
	// for tail calls. Semantically, it combines Call + Return into a single operation.
	OpcodeTailCallReturnCall

	// OpcodeTailCallReturnCallIndirect is the equivalent of OpcodeCallIndirect (a call to a function address)
	// for tail calls. Semantically, it combines CallIndirect + Return into a single operation.
	OpcodeTailCallReturnCallIndirect

	// opcodeEnd marks the end of the opcode list.
	opcodeEnd
)

// returnTypesFn provides the info to determine the type of instruction.
// t1 is the type of the first result, ts are the types of the remaining results.
type returnTypesFn func(b *builder, instr *Value) *types.Type

var (
	returnTypesFnNoReturns    returnTypesFn = func(b *builder, instr *Value) *types.Type { return types.Invalid }
	returnTypesFnSingle                     = func(b *builder, instr *Value) *types.Type { return instr.Type }
	returnTypesFnI32                        = func(b *builder, instr *Value) *types.Type { return types.I32 }
	returnTypesFnF32                        = func(b *builder, instr *Value) *types.Type { return types.F32 }
	returnTypesFnF64                        = func(b *builder, instr *Value) *types.Type { return types.F64 }
	returnTypesFnV128                       = func(b *builder, instr *Value) *types.Type { return types.V128 }
	returnTypesFnCallIndirect               = func(b *builder, instr *Value) *types.Type {
		sigID := types.SignatureID(instr.u1)
		sig, ok := b.signatures[sigID]
		if !ok {
			panic("BUG")
		}
		return types.NewTuple(sig.Results...)
	}
	returnTypesFnCall = func(b *builder, instr *Value) *types.Type {
		sigID := types.SignatureID(instr.u2)
		sig, ok := b.signatures[sigID]
		if !ok {
			panic("BUG")
		}
		return types.NewTuple(sig.Results...)
	}
)

// sideEffect provides the info to determine if an instruction has side effects which
// is used to determine if it can be optimized out, interchanged with others, etc.
type sideEffect byte

const (
	sideEffectUnknown sideEffect = iota
	// sideEffectStrict represents an instruction with side effects, and should be always alive plus cannot be reordered.
	sideEffectStrict
	// sideEffectTraps represents an instruction that can trap, and should be always alive but can be reordered within the group.
	sideEffectTraps
	// sideEffectNone represents an instruction without side effects, and can be eliminated if the result is not used, plus can be reordered within the group.
	sideEffectNone
)

// instructionSideEffects provides the info to determine if an instruction has side effects.
// Instructions with side effects must not be eliminated regardless whether the result is used or not.
var instructionSideEffects = [opcodeEnd]sideEffect{
	OpcodeUndefined:                   sideEffectStrict,
	OpcodeIconst:                      sideEffectNone,
	OpcodeCall:                        sideEffectStrict,
	OpcodeCallIndirect:                sideEffectStrict,
	OpcodeIadd:                        sideEffectNone,
	OpcodeImul:                        sideEffectNone,
	OpcodeIsub:                        sideEffectNone,
	OpcodeIcmp:                        sideEffectNone,
	OpcodeExtractlane:                 sideEffectNone,
	OpcodeInsertlane:                  sideEffectNone,
	OpcodeBand:                        sideEffectNone,
	OpcodeBor:                         sideEffectNone,
	OpcodeBxor:                        sideEffectNone,
	OpcodeRotl:                        sideEffectNone,
	OpcodeRotr:                        sideEffectNone,
	OpcodeFcmp:                        sideEffectNone,
	OpcodeFadd:                        sideEffectNone,
	OpcodeClz:                         sideEffectNone,
	OpcodeCtz:                         sideEffectNone,
	OpcodePopcnt:                      sideEffectNone,
	OpcodeLoad:                        sideEffectNone,
	OpcodeLoadSplat:                   sideEffectNone,
	OpcodeUload8:                      sideEffectNone,
	OpcodeUload16:                     sideEffectNone,
	OpcodeUload32:                     sideEffectNone,
	OpcodeSload8:                      sideEffectNone,
	OpcodeSload16:                     sideEffectNone,
	OpcodeSload32:                     sideEffectNone,
	OpcodeSExtend:                     sideEffectNone,
	OpcodeUExtend:                     sideEffectNone,
	OpcodeSwidenLow:                   sideEffectNone,
	OpcodeUwidenLow:                   sideEffectNone,
	OpcodeSwidenHigh:                  sideEffectNone,
	OpcodeUwidenHigh:                  sideEffectNone,
	OpcodeSnarrow:                     sideEffectNone,
	OpcodeUnarrow:                     sideEffectNone,
	OpcodeSwizzle:                     sideEffectNone,
	OpcodeShuffle:                     sideEffectNone,
	OpcodeSplat:                       sideEffectNone,
	OpcodeFsub:                        sideEffectNone,
	OpcodeF32const:                    sideEffectNone,
	OpcodeF64const:                    sideEffectNone,
	OpcodeIshl:                        sideEffectNone,
	OpcodeSshr:                        sideEffectNone,
	OpcodeUshr:                        sideEffectNone,
	OpcodeStore:                       sideEffectStrict,
	OpcodeIstore8:                     sideEffectStrict,
	OpcodeIstore16:                    sideEffectStrict,
	OpcodeIstore32:                    sideEffectStrict,
	OpcodeExitWithCode:                sideEffectStrict,
	OpcodeExitIfTrueWithCode:          sideEffectStrict,
	OpcodeReturn:                      sideEffectStrict,
	OpcodeFdiv:                        sideEffectNone,
	OpcodeFmul:                        sideEffectNone,
	OpcodeFmax:                        sideEffectNone,
	OpcodeSqmulRoundSat:               sideEffectNone,
	OpcodeSelect:                      sideEffectNone,
	OpcodeFmin:                        sideEffectNone,
	OpcodeFneg:                        sideEffectNone,
	OpcodeFcvtToSint:                  sideEffectTraps,
	OpcodeFcvtToUint:                  sideEffectTraps,
	OpcodeFcvtFromSint:                sideEffectNone,
	OpcodeFcvtFromUint:                sideEffectNone,
	OpcodeFcvtToSintSat:               sideEffectNone,
	OpcodeFcvtToUintSat:               sideEffectNone,
	OpcodeVFcvtFromUint:               sideEffectNone,
	OpcodeVFcvtFromSint:               sideEffectNone,
	OpcodeFdemote:                     sideEffectNone,
	OpcodeFvpromoteLow:                sideEffectNone,
	OpcodeFvdemote:                    sideEffectNone,
	OpcodeFpromote:                    sideEffectNone,
	OpcodeBitcast:                     sideEffectNone,
	OpcodeIreduce:                     sideEffectNone,
	OpcodeSqrt:                        sideEffectNone,
	OpcodeCeil:                        sideEffectNone,
	OpcodeFloor:                       sideEffectNone,
	OpcodeTrunc:                       sideEffectNone,
	OpcodeNearest:                     sideEffectNone,
	OpcodeSdiv:                        sideEffectTraps,
	OpcodeSrem:                        sideEffectTraps,
	OpcodeUdiv:                        sideEffectTraps,
	OpcodeUrem:                        sideEffectTraps,
	OpcodeFabs:                        sideEffectNone,
	OpcodeFcopysign:                   sideEffectNone,
	OpcodeExtIaddPairwise:             sideEffectNone,
	OpcodeVconst:                      sideEffectNone,
	OpcodeVbor:                        sideEffectNone,
	OpcodeVbxor:                       sideEffectNone,
	OpcodeVband:                       sideEffectNone,
	OpcodeVbandnot:                    sideEffectNone,
	OpcodeVbnot:                       sideEffectNone,
	OpcodeVbitselect:                  sideEffectNone,
	OpcodeVanyTrue:                    sideEffectNone,
	OpcodeVallTrue:                    sideEffectNone,
	OpcodeVhighBits:                   sideEffectNone,
	OpcodeVIadd:                       sideEffectNone,
	OpcodeVSaddSat:                    sideEffectNone,
	OpcodeVUaddSat:                    sideEffectNone,
	OpcodeVIsub:                       sideEffectNone,
	OpcodeVSsubSat:                    sideEffectNone,
	OpcodeVUsubSat:                    sideEffectNone,
	OpcodeVIcmp:                       sideEffectNone,
	OpcodeVImin:                       sideEffectNone,
	OpcodeVUmin:                       sideEffectNone,
	OpcodeVImax:                       sideEffectNone,
	OpcodeVUmax:                       sideEffectNone,
	OpcodeVAvgRound:                   sideEffectNone,
	OpcodeVImul:                       sideEffectNone,
	OpcodeVIabs:                       sideEffectNone,
	OpcodeVIneg:                       sideEffectNone,
	OpcodeVIpopcnt:                    sideEffectNone,
	OpcodeVIshl:                       sideEffectNone,
	OpcodeVSshr:                       sideEffectNone,
	OpcodeVUshr:                       sideEffectNone,
	OpcodeVSqrt:                       sideEffectNone,
	OpcodeVFabs:                       sideEffectNone,
	OpcodeVFmin:                       sideEffectNone,
	OpcodeVFmax:                       sideEffectNone,
	OpcodeVFneg:                       sideEffectNone,
	OpcodeVFadd:                       sideEffectNone,
	OpcodeVFsub:                       sideEffectNone,
	OpcodeVFmul:                       sideEffectNone,
	OpcodeVFdiv:                       sideEffectNone,
	OpcodeVFcmp:                       sideEffectNone,
	OpcodeVCeil:                       sideEffectNone,
	OpcodeVFloor:                      sideEffectNone,
	OpcodeVTrunc:                      sideEffectNone,
	OpcodeVNearest:                    sideEffectNone,
	OpcodeVMaxPseudo:                  sideEffectNone,
	OpcodeVMinPseudo:                  sideEffectNone,
	OpcodeVFcvtToUintSat:              sideEffectNone,
	OpcodeVFcvtToSintSat:              sideEffectNone,
	OpcodeVZeroExtLoad:                sideEffectNone,
	OpcodeAtomicRmw:                   sideEffectStrict,
	OpcodeAtomicLoad:                  sideEffectStrict,
	OpcodeAtomicStore:                 sideEffectStrict,
	OpcodeAtomicCas:                   sideEffectStrict,
	OpcodeFence:                       sideEffectStrict,
	OpcodeTailCallReturnCall:          sideEffectStrict,
	OpcodeTailCallReturnCallIndirect:  sideEffectStrict,
	OpcodeWideningPairwiseDotProductS: sideEffectNone,
}

// sideEffect returns true if this instruction has side effects.
func (i *Value) sideEffect() sideEffect {
	if e := instructionSideEffects[i.opcode]; e == sideEffectUnknown {
		panic("BUG: side effect info not registered for " + i.opcode.String())
	} else {
		return e
	}
}

// instructionReturnTypes provides the function to determine the return types of an instruction.
var instructionReturnTypes = [opcodeEnd]returnTypesFn{
	OpcodeExtIaddPairwise:             returnTypesFnV128,
	OpcodeVbor:                        returnTypesFnV128,
	OpcodeVbxor:                       returnTypesFnV128,
	OpcodeVband:                       returnTypesFnV128,
	OpcodeVbnot:                       returnTypesFnV128,
	OpcodeVbandnot:                    returnTypesFnV128,
	OpcodeVbitselect:                  returnTypesFnV128,
	OpcodeVanyTrue:                    returnTypesFnI32,
	OpcodeVallTrue:                    returnTypesFnI32,
	OpcodeVhighBits:                   returnTypesFnI32,
	OpcodeVIadd:                       returnTypesFnV128,
	OpcodeVSaddSat:                    returnTypesFnV128,
	OpcodeVUaddSat:                    returnTypesFnV128,
	OpcodeVIsub:                       returnTypesFnV128,
	OpcodeVSsubSat:                    returnTypesFnV128,
	OpcodeVUsubSat:                    returnTypesFnV128,
	OpcodeVIcmp:                       returnTypesFnV128,
	OpcodeVImin:                       returnTypesFnV128,
	OpcodeVUmin:                       returnTypesFnV128,
	OpcodeVImax:                       returnTypesFnV128,
	OpcodeVUmax:                       returnTypesFnV128,
	OpcodeVImul:                       returnTypesFnV128,
	OpcodeVAvgRound:                   returnTypesFnV128,
	OpcodeVIabs:                       returnTypesFnV128,
	OpcodeVIneg:                       returnTypesFnV128,
	OpcodeVIpopcnt:                    returnTypesFnV128,
	OpcodeVIshl:                       returnTypesFnV128,
	OpcodeVSshr:                       returnTypesFnV128,
	OpcodeVUshr:                       returnTypesFnV128,
	OpcodeExtractlane:                 returnTypesFnSingle,
	OpcodeInsertlane:                  returnTypesFnV128,
	OpcodeBand:                        returnTypesFnSingle,
	OpcodeFcopysign:                   returnTypesFnSingle,
	OpcodeBitcast:                     returnTypesFnSingle,
	OpcodeBor:                         returnTypesFnSingle,
	OpcodeBxor:                        returnTypesFnSingle,
	OpcodeRotl:                        returnTypesFnSingle,
	OpcodeRotr:                        returnTypesFnSingle,
	OpcodeIshl:                        returnTypesFnSingle,
	OpcodeSshr:                        returnTypesFnSingle,
	OpcodeSdiv:                        returnTypesFnSingle,
	OpcodeSrem:                        returnTypesFnSingle,
	OpcodeUdiv:                        returnTypesFnSingle,
	OpcodeUrem:                        returnTypesFnSingle,
	OpcodeUshr:                        returnTypesFnSingle,
	OpcodeUndefined:                   returnTypesFnNoReturns,
	OpcodeIconst:                      returnTypesFnSingle,
	OpcodeSelect:                      returnTypesFnSingle,
	OpcodeSExtend:                     returnTypesFnSingle,
	OpcodeUExtend:                     returnTypesFnSingle,
	OpcodeSwidenLow:                   returnTypesFnV128,
	OpcodeUwidenLow:                   returnTypesFnV128,
	OpcodeSwidenHigh:                  returnTypesFnV128,
	OpcodeUwidenHigh:                  returnTypesFnV128,
	OpcodeSnarrow:                     returnTypesFnV128,
	OpcodeUnarrow:                     returnTypesFnV128,
	OpcodeSwizzle:                     returnTypesFnSingle,
	OpcodeShuffle:                     returnTypesFnV128,
	OpcodeSplat:                       returnTypesFnV128,
	OpcodeIreduce:                     returnTypesFnSingle,
	OpcodeFabs:                        returnTypesFnSingle,
	OpcodeSqrt:                        returnTypesFnSingle,
	OpcodeCeil:                        returnTypesFnSingle,
	OpcodeFloor:                       returnTypesFnSingle,
	OpcodeTrunc:                       returnTypesFnSingle,
	OpcodeNearest:                     returnTypesFnSingle,
	OpcodeCallIndirect:                returnTypesFnCallIndirect,
	OpcodeCall:                        returnTypesFnCall,
	OpcodeLoad:                        returnTypesFnSingle,
	OpcodeVZeroExtLoad:                returnTypesFnV128,
	OpcodeLoadSplat:                   returnTypesFnV128,
	OpcodeIadd:                        returnTypesFnSingle,
	OpcodeIsub:                        returnTypesFnSingle,
	OpcodeImul:                        returnTypesFnSingle,
	OpcodeIcmp:                        returnTypesFnI32,
	OpcodeFcmp:                        returnTypesFnI32,
	OpcodeFadd:                        returnTypesFnSingle,
	OpcodeFsub:                        returnTypesFnSingle,
	OpcodeFdiv:                        returnTypesFnSingle,
	OpcodeFmul:                        returnTypesFnSingle,
	OpcodeFmax:                        returnTypesFnSingle,
	OpcodeFmin:                        returnTypesFnSingle,
	OpcodeSqmulRoundSat:               returnTypesFnV128,
	OpcodeF32const:                    returnTypesFnF32,
	OpcodeF64const:                    returnTypesFnF64,
	OpcodeClz:                         returnTypesFnSingle,
	OpcodeCtz:                         returnTypesFnSingle,
	OpcodePopcnt:                      returnTypesFnSingle,
	OpcodeStore:                       returnTypesFnNoReturns,
	OpcodeIstore8:                     returnTypesFnNoReturns,
	OpcodeIstore16:                    returnTypesFnNoReturns,
	OpcodeIstore32:                    returnTypesFnNoReturns,
	OpcodeExitWithCode:                returnTypesFnNoReturns,
	OpcodeExitIfTrueWithCode:          returnTypesFnNoReturns,
	OpcodeReturn:                      returnTypesFnNoReturns,
	OpcodeUload8:                      returnTypesFnSingle,
	OpcodeUload16:                     returnTypesFnSingle,
	OpcodeUload32:                     returnTypesFnSingle,
	OpcodeSload8:                      returnTypesFnSingle,
	OpcodeSload16:                     returnTypesFnSingle,
	OpcodeSload32:                     returnTypesFnSingle,
	OpcodeFcvtToSint:                  returnTypesFnSingle,
	OpcodeFcvtToUint:                  returnTypesFnSingle,
	OpcodeFcvtFromSint:                returnTypesFnSingle,
	OpcodeFcvtFromUint:                returnTypesFnSingle,
	OpcodeFcvtToSintSat:               returnTypesFnSingle,
	OpcodeFcvtToUintSat:               returnTypesFnSingle,
	OpcodeVFcvtFromUint:               returnTypesFnV128,
	OpcodeVFcvtFromSint:               returnTypesFnV128,
	OpcodeFneg:                        returnTypesFnSingle,
	OpcodeFdemote:                     returnTypesFnF32,
	OpcodeFvdemote:                    returnTypesFnV128,
	OpcodeFvpromoteLow:                returnTypesFnV128,
	OpcodeFpromote:                    returnTypesFnF64,
	OpcodeVconst:                      returnTypesFnV128,
	OpcodeVFabs:                       returnTypesFnV128,
	OpcodeVSqrt:                       returnTypesFnV128,
	OpcodeVFmax:                       returnTypesFnV128,
	OpcodeVFmin:                       returnTypesFnV128,
	OpcodeVFneg:                       returnTypesFnV128,
	OpcodeVFadd:                       returnTypesFnV128,
	OpcodeVFsub:                       returnTypesFnV128,
	OpcodeVFmul:                       returnTypesFnV128,
	OpcodeVFdiv:                       returnTypesFnV128,
	OpcodeVFcmp:                       returnTypesFnV128,
	OpcodeVCeil:                       returnTypesFnV128,
	OpcodeVFloor:                      returnTypesFnV128,
	OpcodeVTrunc:                      returnTypesFnV128,
	OpcodeVNearest:                    returnTypesFnV128,
	OpcodeVMaxPseudo:                  returnTypesFnV128,
	OpcodeVMinPseudo:                  returnTypesFnV128,
	OpcodeVFcvtToUintSat:              returnTypesFnV128,
	OpcodeVFcvtToSintSat:              returnTypesFnV128,
	OpcodeAtomicRmw:                   returnTypesFnSingle,
	OpcodeAtomicLoad:                  returnTypesFnSingle,
	OpcodeAtomicStore:                 returnTypesFnNoReturns,
	OpcodeAtomicCas:                   returnTypesFnSingle,
	OpcodeFence:                       returnTypesFnNoReturns,
	OpcodeTailCallReturnCallIndirect:  returnTypesFnCallIndirect,
	OpcodeTailCallReturnCall:          returnTypesFnCall,
	OpcodeWideningPairwiseDotProductS: returnTypesFnV128,
}
