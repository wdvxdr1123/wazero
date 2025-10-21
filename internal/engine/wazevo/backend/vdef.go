package backend

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
)

// SSAValueDefinition represents a definition of an SSA value.
type SSAValueDefinition struct {
	V ssa.Var
	// Instr is not nil if this is a definition from an instruction.
	Instr *ssa.Value
	// RefCount is the number of references to the result.
	RefCount uint32
}

// IsFromInstr returns true if this definition is from an instruction.
func (d *SSAValueDefinition) IsFromInstr() bool {
	return d.Instr != nil
}
