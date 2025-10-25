package ssa

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
)

// Builder is used to builds SSA consisting of Basic Blocks per function.
func NewBuilder() *Builder {
	return &Builder{
		instructionsPool:        wazevoapi.NewPool(resetValue),
		basicBlocksPool:         wazevoapi.NewPool(resetBasicBlock),
		varLengthBasicBlockPool: wazevoapi.NewVarLengthPool[*BasicBlock](),
		valueAnnotations:        make(map[VarID]string),
		signatures:              make(map[types.SignatureID]*types.Signature),
		returnBlk:               &BasicBlock{id: basicBlockIDReturnBlock, Kind: BlockReturn},
	}
}

// Builder implements Builder interface.
type Builder struct {
	basicBlocksPool  wazevoapi.Pool[BasicBlock]
	instructionsPool wazevoapi.Pool[Value]
	signatures       map[types.SignatureID]*types.Signature
	currentSignature *types.Signature

	// reversePostOrderedBasicBlocks are the BasicBlock(s) ordered in the reverse post-order after passCalculateImmediateDominators.
	reversePostOrderedBasicBlocks []*BasicBlock

	CurrentBlock *BasicBlock
	returnBlk    *BasicBlock

	// nextValueID is used by builder.AllocateValue.
	nextValueID VarID
	// nextVariable is used by builder.AllocateVariable.
	nextVariable uint32

	// valueAnnotations contains the annotations for each Value, only used for debugging.
	valueAnnotations map[VarID]string

	// valuesInfo contains the data per Value used to lower the SSA in backend. This is indexed by ValueID.
	valuesInfo []ValueInfo

	// dominators stores the immediate dominator of each BasicBlock.
	// The index is blockID of the BasicBlock.
	dominators []*BasicBlock
	sparseTree dominatorSparseTree

	varLengthBasicBlockPool wazevoapi.VarLengthPool[*BasicBlock]

	// loopNestingForestRoots are the roots of the loop nesting forest.
	loopNestingForestRoots []*BasicBlock

	// The followings are used for optimization passes/deterministic compilation.
	instStack       []*Value
	blkStack        []*BasicBlock
	blkStack2       []*BasicBlock
	redundantParams []redundantParam

	// blockIterCur is used to implement blockIteratorBegin and blockIteratorNext.
	blockIterCur int

	// doneBlockLayout is true if LayoutBlocks is called.
	doneBlockLayout bool

	currentSourceOffset SourceOffset

	// zeros are the zero value constants for each type.
	zeros map[*types.Type]Var
}

// ValueInfo contains the data per Value used to lower the SSA in backend.
type ValueInfo struct {
	// RefCount is the reference count of the Value.
	RefCount uint32
	alias    Var
}

// redundantParam is a pair of the index of the redundant parameter and the Value.
// This is used to eliminate the redundant parameters in the optimization pass.
type redundantParam struct {
	// index is the index of the redundant parameter in the basicBlock.
	index int
	// uniqueValue is the Value which is passed to the redundant parameter.
	uniqueValue Var
}

// BasicBlock returns the BasicBlock of the given ID.
func (b *Builder) BasicBlock(id BasicBlockID) *BasicBlock {
	if id == basicBlockIDReturnBlock {
		return b.returnBlk
	}
	return b.basicBlocksPool.View(int(id))
}

// InsertZeroValue inserts a zero value constant instruction of the given type.
func (b *Builder) InsertZeroValue(t *types.Type) {
	if _, ok := b.zeros[t]; ok {
		return
	}
	zeroInst := b.AllocateInstruction()
	switch t {
	case types.I32:
		zeroInst.AsIconst32(0)
	case types.I64:
		zeroInst.AsIconst64(0)
	case types.F32:
		zeroInst.AsF32const(0)
	case types.F64:
		zeroInst.AsF64const(0)
	case types.V128:
		zeroInst.AsVconst(0, 0)
	default:
		panic("TODO: " + t.String())
	}
	b.zeros[t] = zeroInst.Insert(b).Return
}

// ReturnBlock returns the BasicBlock which is used to return from the function.
func (b *Builder) ReturnBlock() *BasicBlock {
	return b.returnBlk
}

// Init must be called to reuse this builder for the next function.
func (b *Builder) Init(s *types.Signature) {
	b.nextVariable = 0
	b.currentSignature = s
	b.zeros = make(map[*types.Type]Var)
	resetBasicBlock(b.returnBlk)
	b.instructionsPool.Reset()
	b.basicBlocksPool.Reset()
	b.varLengthBasicBlockPool.Reset()
	b.doneBlockLayout = false
	for _, sig := range b.signatures {
		sig.Used = false
	}

	b.redundantParams = b.redundantParams[:0]
	b.blkStack = b.blkStack[:0]
	b.blkStack2 = b.blkStack2[:0]
	b.dominators = b.dominators[:0]
	b.loopNestingForestRoots = b.loopNestingForestRoots[:0]
	b.basicBlocksPool.Reset()

	for v := VarID(0); v < b.nextValueID; v++ {
		delete(b.valueAnnotations, v)
		b.valuesInfo[v] = ValueInfo{alias: InvalidVar}
	}
	b.nextValueID = 0
	b.reversePostOrderedBasicBlocks = b.reversePostOrderedBasicBlocks[:0]
	b.doneBlockLayout = false
	b.currentSourceOffset = sourceOffsetUnknown
}

// Signature returns the Signature of the currently-compiled function.
func (b *Builder) Signature() *types.Signature {
	return b.currentSignature
}

// AnnotateValue is for debugging purpose.
func (b *Builder) AnnotateValue(value Var, a string) {
	b.valueAnnotations[value.ID()] = a
}

// AllocateInstruction implements Builder.AllocateInstruction.
func (b *Builder) AllocateInstruction() *Value {
	instr := b.instructionsPool.Allocate()
	instr.id = b.instructionsPool.Allocated()
	return instr
}

// DeclareSignature appends the *types.Signature to be referenced by various instructions (e.g. OpcodeCall).
func (b *Builder) DeclareSignature(s *types.Signature) {
	b.signatures[s.ID] = s
	s.Used = false
}

// Signatures returns the slice of declared Signatures.
func (b *Builder) Signatures() (ret []*types.Signature) {
	for _, sig := range b.signatures {
		ret = append(ret, sig)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].ID < ret[j].ID
	})
	return
}

// SetCurrentSourceOffset sets the current source offset. The incoming instruction will be annotated with this offset.
func (b *Builder) SetCurrentSourceOffset(l SourceOffset) {
	b.currentSourceOffset = l
}

func (b *Builder) usedSignatures() (ret []*types.Signature) {
	for _, sig := range b.signatures {
		if sig.Used {
			ret = append(ret, sig)
		}
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].ID < ret[j].ID
	})
	return
}

// ResolveSignature returns the Signature which corresponds to SignatureID.
func (b *Builder) ResolveSignature(id types.SignatureID) *types.Signature {
	return b.signatures[id]
}

// AllocateBasicBlock creates a basic block in SSA function.
func (b *Builder) AllocateBasicBlock() *BasicBlock {
	return b.allocateBasicBlock()
}

// allocateBasicBlock allocates a new basicBlock.
func (b *Builder) allocateBasicBlock() *BasicBlock {
	id := BasicBlockID(b.basicBlocksPool.Allocated())
	blk := b.basicBlocksPool.Allocate()
	blk.id = id
	return blk
}

// Idom returns the immediate dominator of the given BasicBlock.
func (b *Builder) Idom(blk *BasicBlock) *BasicBlock {
	return b.dominators[blk.ID()]
}

// InsertInstruction executes BasicBlock.InsertInstruction for the currently handled basic block.
func (b *Builder) InsertInstruction(instr *Value) {
	b.CurrentBlock.insertInstruction(instr)

	if l := b.currentSourceOffset; l.Valid() {
		// Emit the source offset info only when the instruction has side effect because
		// these are the only instructions that are accessed by stack unwinding.
		// This reduces the significant amount of the offset info in the binary.
		if instr.sideEffect() != sideEffectNone {
			instr.annotateSourceOffset(l)
		}
	}

	var t *types.Type
	resultTypesFn := instructionReturnTypes[instr.opcode]
	if resultTypesFn != nil {
		t = resultTypesFn(b, instr)
	} else if instr.opcode == OpcodeSelectTuple {
		index := instr.u1
		t = instr.Args[0].Type().At(int(index))
	} else {
		panic("TODO: " + instr.Format(b))
	}
	instr.Type = t
	if !t.Invalid() {
		rn := b.allocateValue(t)
		instr.Return = rn.setInstructionID(instr.id)
	}
}

// DefineVariable defines a variable in the `block` with value.
// The defining instruction will be inserted into the `block`.
func (b *Builder) DefineVariable(variable Variable, value Var, block *BasicBlock) {
	block.lastDefinitions[variable] = value
}

// DefineVariableInCurrentBB is the same as DefineVariable except the definition is
// inserted into the current BasicBlock. Alias to DefineVariable(x, y, CurrentBlock()).
func (b *Builder) DefineVariableInCurrentBB(variable Variable, value Var) {
	b.DefineVariable(variable, value, b.CurrentBlock)
}

// EntryBlock returns the entry BasicBlock of the currently-compiled function.
func (b *Builder) EntryBlock() *BasicBlock {
	return b.basicBlocksPool.View(0)
}

// DeclareVariable declares a Variable of the given *types.Type.
func (b *Builder) DeclareVariable(typ *types.Type) Variable {
	v := Variable{id: b.nextVariable}
	b.nextVariable++
	return v.setType(typ)
}

// allocateValue allocates an unused Value.
func (b *Builder) allocateValue(typ *types.Type) (v Var) {
	v = Var{id: b.nextValueID}
	v = v.setType(typ)
	b.nextValueID++
	return
}

// FindValueInLinearPath tries to find the latest definition of the given Variable in the linear path to the current BasicBlock.
// If it cannot find the definition, or it's not sealed yet, it returns ValueInvalid.
func (b *Builder) FindValueInLinearPath(variable Variable) Var {
	return b.findValueInLinearPath(variable, b.CurrentBlock)
}

func (b *Builder) findValueInLinearPath(variable Variable, blk *BasicBlock) Var {
	if val, ok := blk.lastDefinitions[variable]; ok {
		return val
	} else if !blk.sealed {
		return InvalidVar
	}

	if len(blk.Pred) == 1 {
		// If this block is sealed and have only one predecessor,
		// we can use the value in that block without ambiguity on definition.
		return b.findValueInLinearPath(variable, blk.Pred[0])
	}
	return InvalidVar
}

// MustFindValue searches the latest definition of the given Variable and returns the result.
func (b *Builder) MustFindValue(variable Variable) Var {
	return b.findValue(variable.getType(), variable, b.CurrentBlock)
}

// findValue recursively tries to find the latest definition of a `variable`. The algorithm is described in
// the section 2 of the paper https://link.springer.com/content/pdf/10.1007/978-3-642-37051-9_6.pdf.
//
// TODO: reimplement this in iterative, not recursive, to avoid stack overflow.
func (b *Builder) findValue(typ *types.Type, variable Variable, blk *BasicBlock) Var {
	if val, ok := blk.lastDefinitions[variable]; ok {
		// The value is already defined in this block!
		return val
	} else if !blk.sealed { // Incomplete CFG as in the paper.
		// If this is not sealed, that means it might have additional unknown predecessor later on.
		// So we temporarily define the placeholder value here (not add as a parameter yet!),
		// and record it as unknown.
		// The unknown values are resolved when we call seal this block via BasicBlock.Seal().
		value := b.allocateValue(typ)
		if wazevoapi.SSALoggingEnabled {
			fmt.Printf("adding unknown value placeholder for %s at %d\n", variable, blk.id)
		}
		blk.lastDefinitions[variable] = value
		blk.unknownValues = append(blk.unknownValues, unknownValue{
			variable: variable,
			value:    value,
		})
		return value
	} else if blk.EntryBlock() {
		// If this is the entry block, we reach the uninitialized variable which has zero value.
		return b.zeros[variable.getType()]
	}

	if len(blk.Pred) == 1 {
		// If this block is sealed and have only one predecessor,
		// we can use the value in that block without ambiguity on definition.
		return b.findValue(typ, variable, blk.Pred[0])
	} else if len(blk.Pred) == 0 {
		panic("BUG: value is not defined for " + variable.String())
	}

	// If this block has multiple predecessors, we have to gather the definitions,
	// and treat them as an argument to this block.
	//
	// But before that, we have to check if the possible definitions are the same Value.
	tmpValue := b.allocateValue(typ)
	// Break the cycle by defining the variable with the tmpValue.
	b.DefineVariable(variable, tmpValue, blk)
	// Check all the predecessors if they have the same definition.
	uniqueValue := InvalidVar
	for i := range blk.Pred {
		predValue := b.findValue(typ, variable, blk.Pred[i])
		if uniqueValue == InvalidVar {
			uniqueValue = predValue
		} else if uniqueValue != predValue {
			uniqueValue = InvalidVar
			break
		}
	}

	if uniqueValue != InvalidVar {
		// If all the predecessors have the same definition, we can use that value.
		b.alias(tmpValue, uniqueValue)
		return uniqueValue
	} else {
		// Otherwise, add the tmpValue to this block as a parameter which may or may not be redundant, but
		// later we eliminate trivial params in an optimization pass. This must be done before finding the
		// definitions in the predecessors so that we can break the cycle.
		blk.Params = append(blk.Params, tmpValue)
		// After the new param is added, we have to manipulate the original branching instructions
		// in predecessors so that they would pass the definition of `variable` as the argument to
		// the newly added PHI.
		for _, pred := range blk.Pred {
			value := b.findValue(typ, variable, pred)
			pred.addSuccArgument(blk, value)
		}
		return tmpValue
	}
}

// Seal declares that we've known all the predecessors to this block and were added via AddPred.
// After calling this, AddPred will be forbidden.
func (b *Builder) Seal(blk *BasicBlock) {
	blk.sealed = true

	for _, v := range blk.unknownValues {
		variable, phiValue := v.variable, v.value
		typ := variable.getType()
		blk.Params = append(blk.Params, phiValue)
		for _, pred := range blk.Pred {
			predValue := b.findValue(typ, variable, pred)
			if !predValue.Valid() {
				panic("BUG: value is not defined anywhere in the predecessors in the CFG")
			}
			pred.addSuccArgument(blk, predValue)
		}
	}
}

// Format returns the debugging string of the SSA function.
func (b *Builder) Format() string {
	str := strings.Builder{}
	usedSigs := b.usedSignatures()
	if len(usedSigs) > 0 {
		str.WriteByte('\n')
		str.WriteString("signatures:\n")
		for _, sig := range usedSigs {
			str.WriteByte('\t')
			str.WriteString(sig.String())
			str.WriteByte('\n')
		}
	}

	var iterBegin, iterNext func() *BasicBlock
	if b.doneBlockLayout {
		iterBegin, iterNext = b.blockIteratorReversePostOrderBegin, b.blockIteratorReversePostOrderNext
	} else {
		iterBegin, iterNext = b.blockIteratorBegin, b.blockIteratorNext
	}
	for bb := iterBegin(); bb != nil; bb = iterNext() {
		str.WriteByte('\n')
		str.WriteString(bb.formatHeader(b))
		str.WriteByte('\n')

		for _, cur := range bb.Instructions() {
			str.WriteByte('\t')
			str.WriteString(cur.Format(b))
			str.WriteByte('\n')
		}

		str.WriteString(bb.formatEnd(b))
		str.WriteByte('\n')
	}
	return str.String()
}

// BlockIteratorNext advances the state for iteration initialized by BlockIteratorBegin.
// Returns nil if there's no unseen BasicBlock.
func (b *Builder) BlockIteratorNext() *BasicBlock {
	if blk := b.blockIteratorNext(); blk == nil {
		return nil // BasicBlock((*basicBlock)(nil)) != BasicBlock(nil)
	} else {
		return blk
	}
}

// BlockIteratorNext implements Builder.BlockIteratorNext.
func (b *Builder) blockIteratorNext() *BasicBlock {
	index := b.blockIterCur
	for {
		if index == b.basicBlocksPool.Allocated() {
			return nil
		}
		ret := b.basicBlocksPool.View(index)
		index++
		if !ret.invalid {
			b.blockIterCur = index
			return ret
		}
	}
}

// BlockIteratorBegin initializes the state to iterate over all the valid BasicBlock(s) compiled.
// Combined with BlockIteratorNext, we can use this like:
//
//	for blk := builder.BlockIteratorBegin(); blk != nil; blk = builder.BlockIteratorNext() {
//		// ...
//	}
//
// The returned blocks are ordered in the order of AllocateBasicBlock being called.
func (b *Builder) BlockIteratorBegin() *BasicBlock {
	return b.blockIteratorBegin()
}

// BlockIteratorBegin implements Builder.BlockIteratorBegin.
func (b *Builder) blockIteratorBegin() *BasicBlock {
	b.blockIterCur = 0
	return b.blockIteratorNext()
}

// BlockIteratorReversePostOrderBegin is almost the same as BlockIteratorBegin except it returns the BasicBlock in the reverse post-order.
// This is available after RunPasses is run.
func (b *Builder) BlockIteratorReversePostOrderBegin() *BasicBlock {
	return b.blockIteratorReversePostOrderBegin()
}

// BlockIteratorBegin implements Builder.BlockIteratorBegin.
func (b *Builder) blockIteratorReversePostOrderBegin() *BasicBlock {
	b.blockIterCur = 0
	return b.blockIteratorReversePostOrderNext()
}

// BlockIteratorReversePostOrderNext is almost the same as BlockIteratorPostOrderNext except it returns the BasicBlock in the reverse post-order.
// This is available after RunPasses is run.
func (b *Builder) BlockIteratorReversePostOrderNext() *BasicBlock {
	if blk := b.blockIteratorReversePostOrderNext(); blk == nil {
		return nil // BasicBlock((*basicBlock)(nil)) != BasicBlock(nil)
	} else {
		return blk
	}
}

// BlockIteratorNext implements Builder.BlockIteratorNext.
func (b *Builder) blockIteratorReversePostOrderNext() *BasicBlock {
	if b.blockIterCur >= len(b.reversePostOrderedBasicBlocks) {
		return nil
	} else {
		ret := b.reversePostOrderedBasicBlocks[b.blockIterCur]
		b.blockIterCur++
		return ret
	}
}

// ValuesInfo returns the data per Value used to lower the SSA in backend.
// This is indexed by ValueID.
func (b *Builder) ValuesInfo() []ValueInfo {
	return b.valuesInfo
}

// alias records the alias of the given values. The alias(es) will be
// eliminated in the optimization pass via resolveArgumentAlias.
func (b *Builder) alias(dst, src Var) {
	did := int(dst.ID())
	if did >= len(b.valuesInfo) {
		l := did + 1 - len(b.valuesInfo)
		b.valuesInfo = append(b.valuesInfo, make([]ValueInfo, l)...)
		view := b.valuesInfo[len(b.valuesInfo)-l:]
		for i := range view {
			view[i].alias = InvalidVar
		}
	}
	b.valuesInfo[did].alias = src
}

// resolveArgumentAlias resolves the alias of the arguments of the given instruction.
func (b *Builder) resolveArgumentAlias(instr *Value) {
	instr.Args = b.resolveAliases(instr.Args)
}

// resolveAlias resolves the alias of the given value.
func (b *Builder) resolveAlias(v Var) Var {
	info := b.valuesInfo
	l := VarID(len(info))
	// Some aliases are chained, so we need to resolve them recursively.
	for {
		vid := v.ID()
		if vid < l && info[vid].alias.Valid() {
			v = info[vid].alias
		} else {
			break
		}
	}
	return v
}

func (b *Builder) resolveAliases(v []Var) []Var {
	for i, val := range v {
		v[i] = b.resolveAlias(val)
	}
	return v
}

// isDominatedBy returns true if the given block `n` is dominated by the given block `d`.
// Before calling this, the builder must pass by passCalculateImmediateDominators.
func (b *Builder) isDominatedBy(n *BasicBlock, d *BasicBlock) bool {
	if len(b.dominators) == 0 {
		panic("BUG: passCalculateImmediateDominators must be called before calling isDominatedBy")
	}
	ent := b.EntryBlock()
	doms := b.dominators
	for n != d && n != ent {
		n = doms[n.id]
	}
	return n == d
}

// BlockIDMax returns the maximum value of BasicBlocksID existing in the currently-compiled function.
func (b *Builder) BlockIDMax() BasicBlockID {
	return BasicBlockID(b.basicBlocksPool.Allocated())
}

// InsertUndefined inserts an undefined instruction at the current position.
func (b *Builder) InsertUndefined() {
	instr := b.AllocateInstruction()
	instr.opcode = OpcodeUndefined
	b.InsertInstruction(instr)
}

// LoopNestingForestRoots returns the roots of the loop nesting forest.
func (b *Builder) LoopNestingForestRoots() []*BasicBlock {
	return b.loopNestingForestRoots
}

// LowestCommonAncestor returns the lowest common ancestor in the dominator tree of the given BasicBlock(s).
func (b *Builder) LowestCommonAncestor(blk1, blk2 *BasicBlock) *BasicBlock {
	return b.sparseTree.findLCA(blk1.ID(), blk2.ID())
}

// InstructionOfValue returns the Instruction that produces the given Value or nil
// if the Value is not produced by any Instruction.
func (b *Builder) InstructionOfValue(v Var) *Value {
	instrID := v.instructionID()
	if instrID <= 0 {
		return nil
	}
	return b.instructionsPool.View(instrID - 1)
}
