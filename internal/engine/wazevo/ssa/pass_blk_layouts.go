package ssa

import (
	"fmt"
	"strings"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
)

// layoutBlocks implements Builder.LayoutBlocks. This re-organizes builder.reversePostOrderedBasicBlocks.
//
// TODO: there are tons of room for improvement here. e.g. LLVM has BlockPlacementPass using BlockFrequencyInfo,
// BranchProbabilityInfo, and LoopInfo to do a much better job. Also, if we have the profiling instrumentation
// like ball-larus algorithm, then we could do profile-guided optimization. Basically all of them are trying
// to maximize the fall-through opportunities which is most efficient.
//
// Here, fallthrough happens when a block ends with jump instruction whose target is the right next block in the
// builder.reversePostOrderedBasicBlocks.
//
// Currently, we just place blocks using the DFS reverse post-order of the dominator tree with the heuristics:
//  1. a split edge trampoline towards a loop header will be placed as a fallthrough.
//  2. we invert the brz and brnz if it makes the fallthrough more likely.
//
// This heuristic is done in maybeInvertBranches function.
func layoutBlocks(b *Builder) {
	// We might end up splitting critical edges which adds more basic blocks,
	// so we store the currently existing basic blocks in nonSplitBlocks temporarily.
	// That way we can iterate over the original basic blocks while appending new ones into reversePostOrderedBasicBlocks.
	nonSplitBlocks := b.blkStack[:0]
	for i, blk := range b.reversePostOrderedBasicBlocks {
		if !blk.Valid() {
			continue
		}
		nonSplitBlocks = append(nonSplitBlocks, blk)
		if i != len(b.reversePostOrderedBasicBlocks)-1 {
			_ = maybeInvertBranches(blk, b.reversePostOrderedBasicBlocks[i+1])
		}
	}

	var trampolines []*BasicBlock

	// Reset the order slice since we update on the fly by splitting critical edges.
	b.reversePostOrderedBasicBlocks = b.reversePostOrderedBasicBlocks[:0]
	uninsertedTrampolines := b.blkStack2[:0]
	for _, blk := range nonSplitBlocks {
		for i := range blk.Pred {
			pred := blk.Pred[i]
			if pred.visited == 1 || !pred.Valid() {
				continue
			} else if pred.reversePostOrder < blk.reversePostOrder {
				// This means the edge is critical, and this pred is the trampoline and yet to be inserted.
				// Split edge trampolines must come before the destination in reverse post-order.
				b.reversePostOrderedBasicBlocks = append(b.reversePostOrderedBasicBlocks, pred)
				pred.visited = 1 // mark as inserted.
			}
		}

		// Now that we've already added all the potential trampoline blocks incoming to this block,
		// we can add this block itself.
		b.reversePostOrderedBasicBlocks = append(b.reversePostOrderedBasicBlocks, blk)
		blk.visited = 1 // mark as inserted.

		if len(blk.Succ) < 2 {
			// There won't be critical edge originating from this block.
			continue
		} else if blk.Kind == BlockJumpTable {
			// We don't split critical edges here, because at the construction site of BrTable, we already split the edges.
			continue
		}

		for sidx, succ := range blk.Succ {
			if !succ.ReturnBlock() && // If the successor is a return block, we need to split the edge any way because we need "epilogue" to be inserted.
				// Plus if there's no multiple incoming edges to this successor, (pred, succ) is not critical.
				len(succ.Pred) < 2 {
				continue
			}

			// Otherwise, we are sure this is a critical edge. To modify the CFG, we need to find the predecessor info
			// from the successor.
			predIndex := -1
			for i, pred := range succ.Pred { // This linear search should not be a problem since the number of predecessors should almost always small.
				if pred == blk {
					predIndex = i
					break
				}
			}

			if predIndex == -1 {
				// This must be a bug in somewhere around branch manipulation.
				panic("BUG: predecessor info not found while the successor exists in successors list")
			}

			if wazevoapi.SSALoggingEnabled {
				fmt.Printf("trying to split edge from %d->%d at %d\n",
					blk.ID(), succ.ID(), predIndex)
			}

			trampoline := b.splitCriticalEdge(blk, succ, predIndex)
			// Update the successors slice because the target is no longer the original `succ`.
			blk.Succ[sidx] = trampoline

			if wazevoapi.SSAValidationEnabled {
				trampolines = append(trampolines, trampoline)
			}

			if wazevoapi.SSALoggingEnabled {
				fmt.Printf("edge split from %d->%d  as %d->%d->%d \n",
					blk.ID(), succ.ID(),
					blk.ID(), trampoline.ID(), succ.ID())
			}

			if blk.Kind == BlockPlain && blk.Succ[0].id == trampoline.id {
				// This can be lowered as fallthrough at the end of the block.
				b.reversePostOrderedBasicBlocks = append(b.reversePostOrderedBasicBlocks, trampoline)
				trampoline.visited = 1 // mark as inserted.
			} else {
				uninsertedTrampolines = append(uninsertedTrampolines, trampoline)
			}
		}

		for _, trampoline := range uninsertedTrampolines {
			if trampoline.Succ[0].reversePostOrder <= trampoline.reversePostOrder { // "<=", not "<" because the target might be itself.
				// This means the critical edge was backward, so we insert after the current block immediately.
				b.reversePostOrderedBasicBlocks = append(b.reversePostOrderedBasicBlocks, trampoline)
				trampoline.visited = 1 // mark as inserted.
			} // If the target is forward, we can wait to insert until the target is inserted.
		}
		uninsertedTrampolines = uninsertedTrampolines[:0] // Reuse the stack for the next block.
	}

	if wazevoapi.SSALoggingEnabled {
		var bs []string
		for _, blk := range b.reversePostOrderedBasicBlocks {
			bs = append(bs, blk.Name())
		}
		fmt.Println("ordered blocks: ", strings.Join(bs, ", "))
	}

	if wazevoapi.SSAValidationEnabled {
		for _, trampoline := range trampolines {
			if trampoline.visited != 1 {
				panic("BUG: trampoline block not inserted: " + trampoline.formatHeader(b))
			}
			trampoline.validate(b)
		}
	}

	// Reuse the stack for the next iteration.
	b.blkStack2 = uninsertedTrampolines[:0]

	// Finally, mark done.
	b.doneBlockLayout = true
}

// maybeInvertBranches inverts the branch instructions if it is likely possible to the fallthrough more likely with simple heuristics.
// nextInRPO is the next block in the reverse post-order.
//
// Returns true if the branch is inverted for testing purpose.
func maybeInvertBranches(pred, nextInRPO *BasicBlock) bool {
	if pred.Kind == BlockJumpTable {
		return false
	}

	if pred.Kind != BlockIf && pred.Kind != BlockIfNot {
		// If the predecessor is not a conditional branch, we cannot invert the branches.
		return false
	}
	if len(pred.Succ) != 2 {
		panic("If or IfNot should have two successors")
	}

	for _, args := range pred.SuccArguments {
		if len(args) != 0 {
			// If any of the successors has arguments, we cannot invert the branches.
			return false
		}
	}

	// So this block has two branches (a conditional branch followed by an unconditional branch) at the end.
	// We can invert the condition of the branch if it makes the fallthrough more likely.

	condTarget := pred.Succ[0]
	fallthroughTarget := pred.Succ[1]

	if fallthroughTarget.LoopHeader {
		// First, if the tail's target is loopHeader, we don't need to do anything here,
		// because the edge is likely to be critical edge for complex loops (e.g. loop with branches inside it).
		// That means, we will split the edge in the end of LayoutBlocks function, and insert the trampoline block
		// right after this block, which will be fallthrough in any way.
		return false
	} else if condTarget.LoopHeader {
		// On the other hand, if the condBranch's target is loopHeader, we invert the condition of the branch
		// so that we could get the fallthrough to the trampoline block.
		goto invert
	}

	if fallthroughTarget == nextInRPO {
		// Also, if the tail's target is the next block in the reverse post-order, we don't need to do anything here,
		// because if this is not critical edge, we would end up placing these two blocks adjacent to each other.
		// Even if it is the critical edge, we place the trampoline block right after this block, which will be fallthrough in any way.
		return false
	} else if condTarget == nextInRPO {
		// If the condBranch's target is the next block in the reverse post-order, we invert the condition of the branch
		// so that we could get the fallthrough to the block.
		goto invert
	} else {
		return false
	}

invert:
	var invert BasicBlockKind
	switch pred.Kind {
	case BlockIf:
		invert = BlockIfNot
	case BlockIfNot:
		invert = BlockIf
	default:
		panic("BUG: unexpected block kind to invert")
	}
	pred.Kind = invert
	// Swap the successors.
	pred.Succ[0], pred.Succ[1] = pred.Succ[1], pred.Succ[0]
	pred.SuccArguments[0], pred.SuccArguments[1] = pred.SuccArguments[1], pred.SuccArguments[0]
	if wazevoapi.SSALoggingEnabled {
		fmt.Printf("inverting branches at %d->%d and %d->%d\n",
			pred.ID(), fallthroughTarget.ID(), pred.ID(), condTarget.ID())
	}

	return true
}

// splitCriticalEdge splits the critical edge between the given predecessor (`pred`) and successor (owning `predInfo`).
//
// - `pred` is the source of the critical edge,
// - `succ` is the destination of the critical edge,
// - `predInfo` is the predecessor info in the succ.preds slice which represents the critical edge.
//
// Why splitting critical edges is important? See following links:
//
//   - https://en.wikipedia.org/wiki/Control-flow_graph
//   - https://nickdesaulniers.github.io/blog/2023/01/27/critical-edge-splitting/
//
// The returned basic block is the trampoline block which is inserted to split the critical edge.
func (b *Builder) splitCriticalEdge(pred, succ *BasicBlock, predIndex int) *BasicBlock {
	if succ.Pred[predIndex] != pred {
		panic("BUG: predecessor info does not match the given predecessor")
	}

	// In the following, we convert the following CFG:
	//
	//     pred --> succ
	//
	// to the following CFG:
	//
	//     pred --> trampoline -> succ
	//
	// where trampoline is a new basic block which is created to split the critical edge.

	trampoline := b.allocateBasicBlock()
	trampoline.Kind = BlockPlain
	if int(trampoline.id) >= len(b.dominators) {
		b.dominators = append(b.dominators, make([]*BasicBlock, trampoline.id+1)...)
	}
	b.dominators[trampoline.id] = pred

	succIndex := pred.findSucc(succ)
	switch pred.Kind {
	case BlockPlain:
	case BlockIf, BlockIfNot:
	default:
		panic("BUG: critical edge shouldn't be originated from br_table")
	}

	// Replace the original branch with the new branch.
	trampoline.Pred = append(trampoline.Pred, pred) // Do not use []*PredInfo{predInfo} because we might have already allocated the slice.
	trampoline.Succ = append(trampoline.Succ, succ) // Do not use []*basicBlock{pred} because we might have already allocated the slice.
	trampoline.SuccArguments = append(trampoline.SuccArguments, pred.SuccArguments[succIndex])
	pred.SuccArguments[succIndex] = nil
	b.Seal(trampoline)

	// Update the original branch to point to the trampoline.
	succ.Pred[predIndex] = trampoline

	if wazevoapi.SSAValidationEnabled {
		trampoline.validate(b)
	}

	if len(trampoline.Params) > 0 {
		panic("trampoline should not have params")
	}

	// Assign the same order as the original block so that this will be placed before the actual destination.
	trampoline.reversePostOrder = pred.reversePostOrder
	return trampoline
}
