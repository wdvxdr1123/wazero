//go:build amd64
// +build amd64

package jit

import (
	"github.com/twitchyliquid64/golang-asm/obj/x86"
)

// Reserved registers.
const (
	// reservedRegisterForCallEngine: pointer to callEngine (i.e. *callEngine as uintptr)
	reservedRegisterForCallEngine = x86.REG_R13
	// reservedRegisterForStackBasePointerAddress: stack base pointer's address (callEngine.stackBasePointer) in the current function call.
	reservedRegisterForStackBasePointerAddress = x86.REG_R14
	// reservedRegisterForMemory: pointer to the memory slice's data (i.e. &memory.Buffer[0] as uintptr).
	reservedRegisterForMemory    = x86.REG_R15
	reservedRegisterForTemporary = nilRegister
)

const zeroRegister int16 = nilRegister

var (
	generalPurposeFloatRegisters = []int16{
		x86.REG_X0, x86.REG_X1, x86.REG_X2, x86.REG_X3,
		x86.REG_X4, x86.REG_X5, x86.REG_X6, x86.REG_X7,
		x86.REG_X8, x86.REG_X9, x86.REG_X10, x86.REG_X11,
		x86.REG_X12, x86.REG_X13, x86.REG_X14, x86.REG_X15,
	}
	// Note that we never invoke "call" instruction,
	// so we don't need to care about the calling convension.
	// TODO: Maybe it is safe just save rbp, rsp somewhere
	// in Go-allocated variables, and reuse these registers
	// in JITed functions and write them back before returns.
	unreservedGeneralPurposeIntRegisters = []int16{
		x86.REG_AX, x86.REG_CX, x86.REG_DX, x86.REG_BX,
		x86.REG_SI, x86.REG_DI, x86.REG_R8, x86.REG_R9,
		x86.REG_R10, x86.REG_R11, x86.REG_R12,
	}
)

const (
	conditionalRegisterStateE  = conditionalRegisterStateUnset + 1 + iota // ZF equal to zero
	conditionalRegisterStateNE                                            //˜ZF not equal to zero
	conditionalRegisterStateS                                             // SF negative
	conditionalRegisterStateNS                                            // ˜SF non-negative
	conditionalRegisterStateG                                             // ˜(SF xor OF) & ˜ ZF greater (signed >)
	conditionalRegisterStateGE                                            // ˜(SF xor OF) greater or equal (signed >=)
	conditionalRegisterStateL                                             // SF xor OF less (signed <)
	conditionalRegisterStateLE                                            // (SF xor OF) | ZF less or equal (signed <=)
	conditionalRegisterStateA                                             // ˜CF & ˜ZF above (unsigned >)
	conditionalRegisterStateAE                                            // ˜CF above or equal (unsigned >=)
	conditionalRegisterStateB                                             // CF below (unsigned <)
	conditionalRegisterStateBE                                            // CF | ZF below or equal (unsigned <=)
)

// findValueForRegister returns the valueLocation of the given register or nil if not found.
// If not found, return nil.
func (s *valueLocationStack) findValueForRegister(reg int16) *valueLocation {
	for i := uint64(0); i < s.sp; i++ {
		loc := s.stack[i]
		if loc.register == reg {
			return loc
		}
	}
	return nil
}
