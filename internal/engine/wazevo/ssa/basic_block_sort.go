package ssa

import (
	"slices"
)

func sortBlocks(blocks []*BasicBlock) {
	slices.SortFunc(blocks, func(i, j *BasicBlock) int {
		jIsReturn := j.ReturnBlock()
		iIsReturn := i.ReturnBlock()
		if iIsReturn && jIsReturn {
			return 0
		}
		if jIsReturn {
			return 1
		}
		if iIsReturn {
			return -1
		}
		iRoot, jRoot := i.Head(), j.Head()
		if iRoot == nil && jRoot == nil { // For testing.
			return 0
		}
		if jRoot == nil {
			return 1
		}
		if iRoot == nil {
			return -1
		}
		return iRoot.id - jRoot.id
	})
}
