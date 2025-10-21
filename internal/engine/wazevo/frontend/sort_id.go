package frontend

import (
	"slices"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
)

func sortSSAValueIDs(IDs []ssa.VarID) {
	slices.SortFunc(IDs, func(i, j ssa.VarID) int {
		return int(i) - int(j)
	})
}
