//go:build amd64 || arm64
// +build amd64 arm64

package jit

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// TestReservedRegisters ensures that reserved registers are not contained in unreservedGeneralPurposeIntRegisters.
func TestReservedRegisters(t *testing.T) {
	require.NotContains(t, unreservedGeneralPurposeIntRegisters, reservedRegisterForCallEngine)
	require.NotContains(t, unreservedGeneralPurposeIntRegisters, reservedRegisterForStackBasePointerAddress)
	require.NotContains(t, unreservedGeneralPurposeIntRegisters, reservedRegisterForMemory)
	require.NotContains(t, unreservedGeneralPurposeIntRegisters, reservedRegisterForTemporary)
	require.NotContains(t, unreservedGeneralPurposeIntRegisters, zeroRegister)
	require.NotContains(t, unreservedGeneralPurposeIntRegisters, nilRegister)
}

func Test_isIntRegister(t *testing.T) {
	for _, r := range unreservedGeneralPurposeIntRegisters {
		require.True(t, isIntRegister(r))
	}
}

func Test_isFloatRegister(t *testing.T) {
	for _, r := range generalPurposeFloatRegisters {
		require.True(t, isFloatRegister(r))
	}
}

func TestValueLocationStack_basic(t *testing.T) {
	s := newValueLocationStack()
	// Push stack value.
	loc := s.pushValueLocationOnStack()
	require.Equal(t, uint64(1), s.sp)
	require.Equal(t, uint64(0), loc.stackPointer)
	// Push the register value.
	tmpReg := unreservedGeneralPurposeIntRegisters[0]
	loc = s.pushValueLocationOnRegister(tmpReg)
	require.Equal(t, uint64(2), s.sp)
	require.Equal(t, uint64(1), loc.stackPointer)
	require.Equal(t, tmpReg, loc.register)
	require.Contains(t, s.usedRegisters, loc.register)
	// markRegisterUsed.
	tmpReg2 := unreservedGeneralPurposeIntRegisters[1]
	s.markRegisterUsed(tmpReg2)
	require.Contains(t, s.usedRegisters, int16(tmpReg2))
	// releaseRegister.
	s.releaseRegister(loc)
	require.NotContains(t, s.usedRegisters, loc.register)
	require.Equal(t, int16(-1), loc.register)
	// Clone.
	cloned := s.clone()
	require.Equal(t, s.usedRegisters, cloned.usedRegisters)
	require.Equal(t, len(s.stack), len(cloned.stack))
	require.Equal(t, s.sp, cloned.sp)
	for i := 0; i < int(s.sp); i++ {
		actual, exp := s.stack[i], cloned.stack[i]
		require.NotEqual(t, uintptr(unsafe.Pointer(exp)), uintptr(unsafe.Pointer(actual)))
	}
	// Check the max stack pointer.
	for i := 0; i < 1000; i++ {
		s.pushValueLocationOnStack()
	}
	for i := 0; i < 1000; i++ {
		s.pop()
	}
	require.Equal(t, uint64(1001), s.stackPointerCeil)
}

func TestValueLocationStack_takeFreeRegister(t *testing.T) {
	s := newValueLocationStack()
	// For int registers.
	r, ok := s.takeFreeRegister(generalPurposeRegisterTypeInt)
	require.True(t, ok)
	require.True(t, isIntRegister(r))
	// Mark all the int registers used.
	for _, r := range unreservedGeneralPurposeIntRegisters {
		s.markRegisterUsed(r)
	}
	// Now we cannot take free ones for int.
	_, ok = s.takeFreeRegister(generalPurposeRegisterTypeInt)
	require.False(t, ok)
	// But we still should be able to take float regs.
	r, ok = s.takeFreeRegister(generalPurposeRegisterTypeFloat)
	require.True(t, ok)
	require.True(t, isFloatRegister(r))
	// Mark all the float registers used.
	for _, r := range generalPurposeFloatRegisters {
		s.markRegisterUsed(r)
	}
	// Now we cannot take free ones for floats.
	_, ok = s.takeFreeRegister(generalPurposeRegisterTypeFloat)
	require.False(t, ok)
}

func TestValueLocationStack_takeStealTargetFromUsedRegister(t *testing.T) {
	s := newValueLocationStack()
	intReg := unreservedGeneralPurposeIntRegisters[0]
	intLocation := &valueLocation{register: intReg}
	floatReg := generalPurposeFloatRegisters[0]
	floatLocation := &valueLocation{register: floatReg}
	s.push(intLocation)
	s.push(floatLocation)
	// Take for float.
	target, ok := s.takeStealTargetFromUsedRegister(generalPurposeRegisterTypeFloat)
	require.True(t, ok)
	require.Equal(t, floatLocation, target)
	// Take for ints.
	target, ok = s.takeStealTargetFromUsedRegister(generalPurposeRegisterTypeInt)
	require.True(t, ok)
	require.Equal(t, intLocation, target)
	// Pop float value.
	popped := s.pop()
	require.Equal(t, floatLocation, popped)
	// Now we cannot find the steal target.
	target, ok = s.takeStealTargetFromUsedRegister(generalPurposeRegisterTypeFloat)
	require.False(t, ok)
	require.Nil(t, target)
	// Pop int value.
	popped = s.pop()
	require.Equal(t, intLocation, popped)
	// Now we cannot find the steal target.
	target, ok = s.takeStealTargetFromUsedRegister(generalPurposeRegisterTypeInt)
	require.False(t, ok)
	require.Nil(t, target)
}
