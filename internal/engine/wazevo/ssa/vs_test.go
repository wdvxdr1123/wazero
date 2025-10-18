package ssa

import (
	"testing"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

func TestValue_InstructionID(t *testing.T) {
	v := Value(1234).setType(types.I32).setInstructionID(5678)
	require.Equal(t, ValueID(1234), v.ID())
	require.Equal(t, 5678, v.instructionID())
	require.Equal(t, types.I32, v.Type())
}
