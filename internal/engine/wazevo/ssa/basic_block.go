package ssa

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
)

// BasicBlock represents the Basic Block of an SSA function.
// Each BasicBlock always ends with branching instructions (e.g. Branch, Return, etc.),
// and at most two branches are allowed. If there's two branches, these two are placed together at the end of the block.
// In other words, there's no branching instruction in the middle of the block.
//
// Note: we use the "block argument" variant of SSA, instead of PHI functions. See the package level doc comments.
//
// Note: we use "parameter/param" as a placeholder which represents a variant of PHI, and "argument/arg" as an actual
// Value passed to that "parameter/param".
type BasicBlock struct {
	id    BasicBlockID
	instr []*Instruction
	// Params are Values that represent parameters to a basicBlock.
	// Each parameter can be considered as an output of PHI instruction in traditional SSA.
	Params []Value
	Pred   []PredInfo
	Succ   []*BasicBlock
	// lastDefinitions maps Variable to its last definition in this block.
	lastDefinitions map[Variable]Value
	// unknownsValues are used in builder.findValue. The usage is well-described in the paper.
	unknownValues []unknownValue
	// invalid is true if this block is made invalid during optimizations.
	invalid bool
	// sealed is true if this is sealed (all the predecessors are known).
	sealed bool

	// loopHeader is true if this block is a loop header:
	//
	// > A loop header (sometimes called the entry point of the loop) is a dominator that is the target
	// > of a loop-forming back edge. The loop header dominates all blocks in the loop body.
	// > A block may be a loop header for more than one loop. A loop may have multiple entry points,
	// > in which case it has no "loop header".
	//
	// See https://en.wikipedia.org/wiki/Control-flow_graph for more details.
	//
	// This is modified during the subPassLoopDetection pass.
	LoopHeader bool

	// loopNestingForestChildren holds the children of this block in the loop nesting forest.
	// Non-empty if and only if this block is a loop header (i.e. loopHeader=true)
	loopNestingForestChildren wazevoapi.VarLength[*BasicBlock]

	// reversePostOrder is used to sort all the blocks in the function in reverse post order.
	// This is used in builder.LayoutBlocks.
	reversePostOrder int32

	// visited is used during various traversals.
	visited int32

	// child and sibling are the ones in the dominator tree.
	child, sibling *BasicBlock
}

type (
	// BasicBlockID is the unique ID of a basicBlock.
	BasicBlockID uint32

	unknownValue struct {
		// variable is the variable that this unknownValue represents.
		variable Variable
		// value is the value that this unknownValue represents.
		value Value
	}
)

// basicBlockVarLengthNil is the default nil value for basicBlock.loopNestingForestChildren.
var basicBlockVarLengthNil = wazevoapi.NewNilVarLength[*BasicBlock]()

const basicBlockIDReturnBlock = 0xffffffff

// Name returns the unique string ID of this block. e.g. blk0, blk1, ...
func (bb *BasicBlock) Name() string {
	if bb.id == basicBlockIDReturnBlock {
		return "blk_ret"
	} else {
		return fmt.Sprintf("blk%d", bb.id)
	}
}

// String implements fmt.Stringer for debugging.
func (bid BasicBlockID) String() string {
	if bid == basicBlockIDReturnBlock {
		return "blk_ret"
	} else {
		return fmt.Sprintf("blk%d", bid)
	}
}

// ID returns the unique ID of this block.
func (bb *BasicBlock) ID() BasicBlockID {
	return bb.id
}

// PredInfo is the information of a predecessor of a basicBlock.
// predecessor is determined by a pair of block and the branch instruction used to jump to the successor.
type PredInfo struct {
	Block  *BasicBlock
	Branch *Instruction
}

func (bb *BasicBlock) EntryBlock() bool {
	return bb.id == 0
}

func (bb *BasicBlock) ReturnBlock() bool {
	return bb.id == basicBlockIDReturnBlock
}

func (bb *BasicBlock) AddParam(b Builder, typ types.Type) Value {
	paramValue := b.allocateValue(typ)
	bb.Params = append(bb.Params, paramValue)
	return paramValue
}

// Valid is true if this block is still valid even after optimizations.
func (bb *BasicBlock) Valid() bool {
	return !bb.invalid
}

// Sealed is true if this block has been sealed.
func (bb *BasicBlock) Sealed() bool {
	return bb.sealed
}

// insertInstruction implements BasicBlock.InsertInstruction.
func (bb *BasicBlock) insertInstruction(b *builder, next *Instruction) {
	bb.instr = append(bb.instr, next)

	switch next.opcode {
	case OpcodeJump, OpcodeBrz, OpcodeBrnz:
		target := BasicBlockID(next.rValue)
		b.basicBlock(target).addPred(bb, next)
	case OpcodeBrTable:
		for _, _target := range next.rValues {
			target := BasicBlockID(_target)
			b.basicBlock(target).addPred(bb, next)
		}
	}
}

// Instructions returns the list of instructions in this block.
func (bb *BasicBlock) Instructions() []*Instruction {
	return bb.instr
}

// Head returns the head instruction of this block.
func (bb *BasicBlock) Head() *Instruction {
	if len(bb.instr) == 0 {
		return nil
	}
	return bb.instr[0]
}

// Tail returns the tail instruction of this block.
func (bb *BasicBlock) Tail() *Instruction {
	if len(bb.instr) == 0 {
		return nil
	}
	return bb.instr[len(bb.instr)-1]
}

// reset resets the basicBlock to its initial state so that it can be reused for another function.
func resetBasicBlock(bb *BasicBlock) {
	bb.Params = bb.Params[:0]
	bb.instr = bb.instr[:0]
	bb.Pred = bb.Pred[:0]
	bb.Succ = bb.Succ[:0]
	bb.invalid, bb.sealed = false, false
	bb.unknownValues = bb.unknownValues[:0]
	bb.lastDefinitions = wazevoapi.ResetMap(bb.lastDefinitions)
	bb.reversePostOrder = -1
	bb.visited = 0
	bb.loopNestingForestChildren = basicBlockVarLengthNil
	bb.LoopHeader = false
	bb.sibling = nil
	bb.child = nil
}

// addPred adds a predecessor to this block specified by the branch instruction.
func (bb *BasicBlock) addPred(pred *BasicBlock, branch *Instruction) {
	if bb.sealed {
		panic("BUG: trying to add predecessor to a sealed block: " + bb.Name())
	}

	for i := range bb.Pred {
		existingPred := bb.Pred[i]
		if existingPred.Block == pred && existingPred.Branch != branch {
			// If the target is already added, then this must come from the same BrTable,
			// otherwise such redundant branch should be eliminated by the frontend. (which should be simpler).
			panic(fmt.Sprintf("BUG: redundant non BrTable jumps in %s whose targes are the same", bb.Name()))
		}
	}

	bb.Pred = append(bb.Pred, PredInfo{
		Block:  pred,
		Branch: branch,
	})

	pred.Succ = append(pred.Succ, bb)
}

// formatHeader returns the string representation of the header of the basicBlock.
func (bb *BasicBlock) formatHeader(b Builder) string {
	ps := make([]string, len(bb.Params))
	for i, p := range bb.Params {
		ps[i] = p.formatWithType(b)
	}

	if len(bb.Pred) > 0 {
		preds := make([]string, 0, len(bb.Pred))
		for _, pred := range bb.Pred {
			if pred.Block.invalid {
				continue
			}
			preds = append(preds, fmt.Sprintf("blk%d", pred.Block.id))

		}
		return fmt.Sprintf("blk%d: (%s) <-- (%s)",
			bb.id, strings.Join(ps, ","), strings.Join(preds, ","))
	} else {
		return fmt.Sprintf("blk%d: (%s)", bb.id, strings.Join(ps, ", "))
	}
}

// validates validates the basicBlock for debugging purpose.
func (bb *BasicBlock) validate(b *builder) {
	if bb.invalid {
		panic("BUG: trying to validate an invalid block: " + bb.Name())
	}
	if len(bb.Pred) > 0 {
		for _, pred := range bb.Pred {
			if pred.Branch.opcode != OpcodeBrTable {
				blockID := int(pred.Branch.rValue)
				target := b.basicBlocksPool.View(blockID)
				if target != bb {
					panic(fmt.Sprintf("BUG: '%s' is not branch to %s, but to %s",
						pred.Branch.Format(b), bb.Name(), target.Name()))
				}
			}

			var exp int
			if bb.ReturnBlock() {
				exp = len(b.currentSignature.Results)
			} else {
				exp = len(bb.Params)
			}

			if len(pred.Branch.vs) != exp {
				panic(fmt.Sprintf(
					"BUG: len(argument at %s) != len(params at %s): %d != %d: %s",
					pred.Block.Name(), bb.Name(),
					len(pred.Branch.vs), len(bb.Params), pred.Branch.Format(b),
				))
			}

		}
	}
}

// String implements fmt.Stringer for debugging purpose only.
func (bb *BasicBlock) String() string {
	return strconv.Itoa(int(bb.id))
}

// LoopNestingForestChildren returns the children of this block in the loop nesting forest.
func (bb *BasicBlock) LoopNestingForestChildren() []*BasicBlock {
	return bb.loopNestingForestChildren.View()
}
