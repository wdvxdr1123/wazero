package ssa

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
)

// Builder is used to builds SSA consisting of Basic Blocks per function.
type Builder interface {
	// Init must be called to reuse this builder for the next function.
	Init(typ *types.Signature)

	// Signature returns the Signature of the currently-compiled function.
	Signature() *types.Signature

	// BlockIDMax returns the maximum value of BasicBlocksID existing in the currently-compiled function.
	BlockIDMax() BasicBlockID

	// AllocateBasicBlock creates a basic block in SSA function.
	AllocateBasicBlock() *BasicBlock

	// CurrentBlock returns the currently handled BasicBlock which is set by the latest call to SetCurrentBlock.
	CurrentBlock() *BasicBlock

	// EntryBlock returns the entry BasicBlock of the currently-compiled function.
	EntryBlock() *BasicBlock

	// SetCurrentBlock sets the instruction insertion target to the BasicBlock `b`.
	SetCurrentBlock(b *BasicBlock)

	// DeclareVariable declares a Variable of the given *types.Type.
	DeclareVariable(*types.Type) Variable

	// DefineVariable defines a variable in the `block` with value.
	// The defining instruction will be inserted into the `block`.
	DefineVariable(variable Variable, value Value, block *BasicBlock)

	// DefineVariableInCurrentBB is the same as DefineVariable except the definition is
	// inserted into the current BasicBlock. Alias to DefineVariable(x, y, CurrentBlock()).
	DefineVariableInCurrentBB(variable Variable, value Value)

	// AllocateInstruction returns a new Instruction.
	AllocateInstruction() *Instruction

	// InsertInstruction executes BasicBlock.InsertInstruction for the currently handled basic block.
	InsertInstruction(raw *Instruction)

	// allocateValue allocates an unused Value.
	allocateValue(typ *types.Type) Value

	// MustFindValue searches the latest definition of the given Variable and returns the result.
	MustFindValue(variable Variable) Value

	// FindValueInLinearPath tries to find the latest definition of the given Variable in the linear path to the current BasicBlock.
	// If it cannot find the definition, or it's not sealed yet, it returns ValueInvalid.
	FindValueInLinearPath(variable Variable) Value

	// Seal declares that we've known all the predecessors to this block and were added via AddPred.
	// After calling this, AddPred will be forbidden.
	Seal(blk *BasicBlock)

	// AnnotateValue is for debugging purpose.
	AnnotateValue(value Value, annotation string)

	// DeclareSignature appends the *types.Signature to be referenced by various instructions (e.g. OpcodeCall).
	DeclareSignature(signature *types.Signature)

	// Signatures returns the slice of declared Signatures.
	Signatures() []*types.Signature

	// ResolveSignature returns the Signature which corresponds to SignatureID.
	ResolveSignature(id types.SignatureID) *types.Signature

	// RunPasses runs various passes on the constructed SSA function.
	RunPasses()

	// Format returns the debugging string of the SSA function.
	Format() string

	// BlockIteratorBegin initializes the state to iterate over all the valid BasicBlock(s) compiled.
	// Combined with BlockIteratorNext, we can use this like:
	//
	// 	for blk := builder.BlockIteratorBegin(); blk != nil; blk = builder.BlockIteratorNext() {
	// 		// ...
	//	}
	//
	// The returned blocks are ordered in the order of AllocateBasicBlock being called.
	BlockIteratorBegin() *BasicBlock

	// BlockIteratorNext advances the state for iteration initialized by BlockIteratorBegin.
	// Returns nil if there's no unseen BasicBlock.
	BlockIteratorNext() *BasicBlock

	// ValuesInfo returns the data per Value used to lower the SSA in backend.
	// This is indexed by ValueID.
	ValuesInfo() []ValueInfo

	// BlockIteratorReversePostOrderBegin is almost the same as BlockIteratorBegin except it returns the BasicBlock in the reverse post-order.
	// This is available after RunPasses is run.
	BlockIteratorReversePostOrderBegin() *BasicBlock

	// BlockIteratorReversePostOrderNext is almost the same as BlockIteratorPostOrderNext except it returns the BasicBlock in the reverse post-order.
	// This is available after RunPasses is run.
	BlockIteratorReversePostOrderNext() *BasicBlock

	// ReturnBlock returns the BasicBlock which is used to return from the function.
	ReturnBlock() *BasicBlock

	// InsertUndefined inserts an undefined instruction at the current position.
	InsertUndefined()

	// SetCurrentSourceOffset sets the current source offset. The incoming instruction will be annotated with this offset.
	SetCurrentSourceOffset(line SourceOffset)

	// LoopNestingForestRoots returns the roots of the loop nesting forest.
	LoopNestingForestRoots() []*BasicBlock

	// LowestCommonAncestor returns the lowest common ancestor in the dominator tree of the given BasicBlock(s).
	LowestCommonAncestor(blk1, blk2 *BasicBlock) *BasicBlock

	// Idom returns the immediate dominator of the given BasicBlock.
	Idom(blk *BasicBlock) *BasicBlock

	// InsertZeroValue inserts a zero value constant instruction of the given type.
	InsertZeroValue(t *types.Type)

	// BasicBlock returns the BasicBlock of the given ID.
	BasicBlock(id BasicBlockID) *BasicBlock

	// InstructionOfValue returns the Instruction that produces the given Value or nil if the Value is not produced by any Instruction.
	InstructionOfValue(v Value) *Instruction
}

// NewBuilder returns a new Builder implementation.
func NewBuilder() Builder {
	return &builder{
		instructionsPool:        wazevoapi.NewPool(resetInstruction),
		basicBlocksPool:         wazevoapi.NewPool(resetBasicBlock),
		varLengthBasicBlockPool: wazevoapi.NewVarLengthPool[*BasicBlock](),
		valueAnnotations:        make(map[ValueID]string),
		signatures:              make(map[types.SignatureID]*types.Signature),
		returnBlk:               &BasicBlock{id: basicBlockIDReturnBlock, Kind: BlockReturn},
	}
}

// builder implements Builder interface.
type builder struct {
	basicBlocksPool  wazevoapi.Pool[BasicBlock]
	instructionsPool wazevoapi.Pool[Instruction]
	signatures       map[types.SignatureID]*types.Signature
	currentSignature *types.Signature

	// reversePostOrderedBasicBlocks are the BasicBlock(s) ordered in the reverse post-order after passCalculateImmediateDominators.
	reversePostOrderedBasicBlocks []*BasicBlock
	currentBB                     *BasicBlock
	returnBlk                     *BasicBlock

	// nextValueID is used by builder.AllocateValue.
	nextValueID ValueID
	// nextVariable is used by builder.AllocateVariable.
	nextVariable uint32

	// valueAnnotations contains the annotations for each Value, only used for debugging.
	valueAnnotations map[ValueID]string

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
	instStack       []*Instruction
	blkStack        []*BasicBlock
	blkStack2       []*BasicBlock
	redundantParams []redundantParam

	// blockIterCur is used to implement blockIteratorBegin and blockIteratorNext.
	blockIterCur int

	// doneBlockLayout is true if LayoutBlocks is called.
	doneBlockLayout bool

	currentSourceOffset SourceOffset

	// zeros are the zero value constants for each type.
	zeros map[*types.Type]Value
}

// ValueInfo contains the data per Value used to lower the SSA in backend.
type ValueInfo struct {
	// RefCount is the reference count of the Value.
	RefCount uint32
	alias    Value
}

// redundantParam is a pair of the index of the redundant parameter and the Value.
// This is used to eliminate the redundant parameters in the optimization pass.
type redundantParam struct {
	// index is the index of the redundant parameter in the basicBlock.
	index int
	// uniqueValue is the Value which is passed to the redundant parameter.
	uniqueValue Value
}

// BasicBlock implements Builder.BasicBlock.
func (b *builder) BasicBlock(id BasicBlockID) *BasicBlock {
	return b.basicBlock(id)
}

func (b *builder) basicBlock(id BasicBlockID) *BasicBlock {
	if id == basicBlockIDReturnBlock {
		return b.returnBlk
	}
	return b.basicBlocksPool.View(int(id))
}

// InsertZeroValue implements Builder.InsertZeroValue.
func (b *builder) InsertZeroValue(t *types.Type) {
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
	b.zeros[t] = zeroInst.Insert(b).Return()
}

// ReturnBlock implements Builder.ReturnBlock.
func (b *builder) ReturnBlock() *BasicBlock {
	return b.returnBlk
}

// Init implements Builder.Reset.
func (b *builder) Init(s *types.Signature) {
	b.nextVariable = 0
	b.currentSignature = s
	b.zeros = make(map[*types.Type]Value)
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

	for v := ValueID(0); v < b.nextValueID; v++ {
		delete(b.valueAnnotations, v)
		b.valuesInfo[v] = ValueInfo{alias: ValueInvalid}
	}
	b.nextValueID = 0
	b.reversePostOrderedBasicBlocks = b.reversePostOrderedBasicBlocks[:0]
	b.doneBlockLayout = false
	b.currentSourceOffset = sourceOffsetUnknown
}

// Signature implements Builder.Signature.
func (b *builder) Signature() *types.Signature {
	return b.currentSignature
}

// AnnotateValue implements Builder.AnnotateValue.
func (b *builder) AnnotateValue(value Value, a string) {
	b.valueAnnotations[value.ID()] = a
}

// AllocateInstruction implements Builder.AllocateInstruction.
func (b *builder) AllocateInstruction() *Instruction {
	instr := b.instructionsPool.Allocate()
	instr.id = b.instructionsPool.Allocated()
	return instr
}

// DeclareSignature implements Builder.AnnotateValue.
func (b *builder) DeclareSignature(s *types.Signature) {
	b.signatures[s.ID] = s
	s.Used = false
}

// Signatures implements Builder.Signatures.
func (b *builder) Signatures() (ret []*types.Signature) {
	for _, sig := range b.signatures {
		ret = append(ret, sig)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].ID < ret[j].ID
	})
	return
}

// SetCurrentSourceOffset implements Builder.SetCurrentSourceOffset.
func (b *builder) SetCurrentSourceOffset(l SourceOffset) {
	b.currentSourceOffset = l
}

func (b *builder) usedSignatures() (ret []*types.Signature) {
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

// ResolveSignature implements Builder.ResolveSignature.
func (b *builder) ResolveSignature(id types.SignatureID) *types.Signature {
	return b.signatures[id]
}

// AllocateBasicBlock implements Builder.AllocateBasicBlock.
func (b *builder) AllocateBasicBlock() *BasicBlock {
	return b.allocateBasicBlock()
}

// allocateBasicBlock allocates a new basicBlock.
func (b *builder) allocateBasicBlock() *BasicBlock {
	id := BasicBlockID(b.basicBlocksPool.Allocated())
	blk := b.basicBlocksPool.Allocate()
	blk.id = id
	return blk
}

// Idom implements Builder.Idom.
func (b *builder) Idom(blk *BasicBlock) *BasicBlock {
	return b.dominators[blk.ID()]
}

// InsertInstruction implements Builder.InsertInstruction.
func (b *builder) InsertInstruction(instr *Instruction) {
	b.currentBB.insertInstruction(b, instr)

	if l := b.currentSourceOffset; l.Valid() {
		// Emit the source offset info only when the instruction has side effect because
		// these are the only instructions that are accessed by stack unwinding.
		// This reduces the significant amount of the offset info in the binary.
		if instr.sideEffect() != sideEffectNone {
			instr.annotateSourceOffset(l)
		}
	}

	resultTypesFn := instructionReturnTypes[instr.opcode]
	if resultTypesFn == nil {
		panic("TODO: " + instr.Format(b))
	}

	t1, ts := resultTypesFn(b, instr)
	if t1.Invalid() {
		return
	}

	r1 := b.allocateValue(t1)
	instr.rValue = r1.setInstructionID(instr.id)

	tsl := len(ts)
	if tsl == 0 {
		return
	}

	rValues := make([]Value, 0, tsl)
	for i := 0; i < tsl; i++ {
		rn := b.allocateValue(ts[i])
		rValues = append(rValues, rn.setInstructionID(instr.id))
	}
	instr.rValues = rValues
}

// DefineVariable implements Builder.DefineVariable.
func (b *builder) DefineVariable(variable Variable, value Value, block *BasicBlock) {
	block.lastDefinitions[variable] = value
}

// DefineVariableInCurrentBB implements Builder.DefineVariableInCurrentBB.
func (b *builder) DefineVariableInCurrentBB(variable Variable, value Value) {
	b.DefineVariable(variable, value, b.currentBB)
}

// SetCurrentBlock implements Builder.SetCurrentBlock.
func (b *builder) SetCurrentBlock(bb *BasicBlock) {
	b.currentBB = bb
}

// CurrentBlock implements Builder.CurrentBlock.
func (b *builder) CurrentBlock() *BasicBlock {
	return b.currentBB
}

// EntryBlock implements Builder.EntryBlock.
func (b *builder) EntryBlock() *BasicBlock {
	return b.entryBlk()
}

// DeclareVariable implements Builder.DeclareVariable.
func (b *builder) DeclareVariable(typ *types.Type) Variable {
	v := Variable{id: b.nextVariable}
	b.nextVariable++
	return v.setType(typ)
}

// allocateValue implements Builder.AllocateValue.
func (b *builder) allocateValue(typ *types.Type) (v Value) {
	v = Value{id: b.nextValueID}
	v = v.setType(typ)
	b.nextValueID++
	return
}

// FindValueInLinearPath implements Builder.FindValueInLinearPath.
func (b *builder) FindValueInLinearPath(variable Variable) Value {
	return b.findValueInLinearPath(variable, b.currentBB)
}

func (b *builder) findValueInLinearPath(variable Variable, blk *BasicBlock) Value {
	if val, ok := blk.lastDefinitions[variable]; ok {
		return val
	} else if !blk.sealed {
		return ValueInvalid
	}

	if len(blk.Pred) == 1 {
		// If this block is sealed and have only one predecessor,
		// we can use the value in that block without ambiguity on definition.
		return b.findValueInLinearPath(variable, blk.Pred[0])
	}
	return ValueInvalid
}

// MustFindValue implements Builder.MustFindValue.
func (b *builder) MustFindValue(variable Variable) Value {
	return b.findValue(variable.getType(), variable, b.currentBB)
}

// findValue recursively tries to find the latest definition of a `variable`. The algorithm is described in
// the section 2 of the paper https://link.springer.com/content/pdf/10.1007/978-3-642-37051-9_6.pdf.
//
// TODO: reimplement this in iterative, not recursive, to avoid stack overflow.
func (b *builder) findValue(typ *types.Type, variable Variable, blk *BasicBlock) Value {
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
	uniqueValue := ValueInvalid
	for i := range blk.Pred {
		predValue := b.findValue(typ, variable, blk.Pred[i])
		if uniqueValue == ValueInvalid {
			uniqueValue = predValue
		} else if uniqueValue != predValue {
			uniqueValue = ValueInvalid
			break
		}
	}

	if uniqueValue != ValueInvalid {
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

// Seal implements Builder.Seal.
func (b *builder) Seal(blk *BasicBlock) {
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

// Format implements Builder.Format.
func (b *builder) Format() string {
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

// BlockIteratorNext implements Builder.BlockIteratorNext.
func (b *builder) BlockIteratorNext() *BasicBlock {
	if blk := b.blockIteratorNext(); blk == nil {
		return nil // BasicBlock((*basicBlock)(nil)) != BasicBlock(nil)
	} else {
		return blk
	}
}

// BlockIteratorNext implements Builder.BlockIteratorNext.
func (b *builder) blockIteratorNext() *BasicBlock {
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

// BlockIteratorBegin implements Builder.BlockIteratorBegin.
func (b *builder) BlockIteratorBegin() *BasicBlock {
	return b.blockIteratorBegin()
}

// BlockIteratorBegin implements Builder.BlockIteratorBegin.
func (b *builder) blockIteratorBegin() *BasicBlock {
	b.blockIterCur = 0
	return b.blockIteratorNext()
}

// BlockIteratorReversePostOrderBegin implements Builder.BlockIteratorReversePostOrderBegin.
func (b *builder) BlockIteratorReversePostOrderBegin() *BasicBlock {
	return b.blockIteratorReversePostOrderBegin()
}

// BlockIteratorBegin implements Builder.BlockIteratorBegin.
func (b *builder) blockIteratorReversePostOrderBegin() *BasicBlock {
	b.blockIterCur = 0
	return b.blockIteratorReversePostOrderNext()
}

// BlockIteratorReversePostOrderNext implements Builder.BlockIteratorReversePostOrderNext.
func (b *builder) BlockIteratorReversePostOrderNext() *BasicBlock {
	if blk := b.blockIteratorReversePostOrderNext(); blk == nil {
		return nil // BasicBlock((*basicBlock)(nil)) != BasicBlock(nil)
	} else {
		return blk
	}
}

// BlockIteratorNext implements Builder.BlockIteratorNext.
func (b *builder) blockIteratorReversePostOrderNext() *BasicBlock {
	if b.blockIterCur >= len(b.reversePostOrderedBasicBlocks) {
		return nil
	} else {
		ret := b.reversePostOrderedBasicBlocks[b.blockIterCur]
		b.blockIterCur++
		return ret
	}
}

// ValuesInfo implements Builder.ValuesInfo.
func (b *builder) ValuesInfo() []ValueInfo {
	return b.valuesInfo
}

// alias records the alias of the given values. The alias(es) will be
// eliminated in the optimization pass via resolveArgumentAlias.
func (b *builder) alias(dst, src Value) {
	did := int(dst.ID())
	if did >= len(b.valuesInfo) {
		l := did + 1 - len(b.valuesInfo)
		b.valuesInfo = append(b.valuesInfo, make([]ValueInfo, l)...)
		view := b.valuesInfo[len(b.valuesInfo)-l:]
		for i := range view {
			view[i].alias = ValueInvalid
		}
	}
	b.valuesInfo[did].alias = src
}

// resolveArgumentAlias resolves the alias of the arguments of the given instruction.
func (b *builder) resolveArgumentAlias(instr *Instruction) {
	if instr.v.Valid() {
		instr.v = b.resolveAlias(instr.v)
	}

	if instr.v2.Valid() {
		instr.v2 = b.resolveAlias(instr.v2)
	}

	if instr.v3.Valid() {
		instr.v3 = b.resolveAlias(instr.v3)
	}

	instr.vs = b.resolveAliases(instr.vs)
}

// resolveAlias resolves the alias of the given value.
func (b *builder) resolveAlias(v Value) Value {
	info := b.valuesInfo
	l := ValueID(len(info))
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

func (b *builder) resolveAliases(v []Value) []Value {
	for i, val := range v {
		v[i] = b.resolveAlias(val)
	}
	return v
}

// entryBlk returns the entry block of the function.
func (b *builder) entryBlk() *BasicBlock {
	return b.basicBlocksPool.View(0)
}

// isDominatedBy returns true if the given block `n` is dominated by the given block `d`.
// Before calling this, the builder must pass by passCalculateImmediateDominators.
func (b *builder) isDominatedBy(n *BasicBlock, d *BasicBlock) bool {
	if len(b.dominators) == 0 {
		panic("BUG: passCalculateImmediateDominators must be called before calling isDominatedBy")
	}
	ent := b.entryBlk()
	doms := b.dominators
	for n != d && n != ent {
		n = doms[n.id]
	}
	return n == d
}

// BlockIDMax implements Builder.BlockIDMax.
func (b *builder) BlockIDMax() BasicBlockID {
	return BasicBlockID(b.basicBlocksPool.Allocated())
}

// InsertUndefined implements Builder.InsertUndefined.
func (b *builder) InsertUndefined() {
	instr := b.AllocateInstruction()
	instr.opcode = OpcodeUndefined
	b.InsertInstruction(instr)
}

// LoopNestingForestRoots implements Builder.LoopNestingForestRoots.
func (b *builder) LoopNestingForestRoots() []*BasicBlock {
	return b.loopNestingForestRoots
}

// LowestCommonAncestor implements Builder.LowestCommonAncestor.
func (b *builder) LowestCommonAncestor(blk1, blk2 *BasicBlock) *BasicBlock {
	return b.sparseTree.findLCA(blk1.ID(), blk2.ID())
}

// InstructionOfValue returns the instruction that produces the given Value, or nil
// if the Value is not produced by any instruction.
func (b *builder) InstructionOfValue(v Value) *Instruction {
	instrID := v.instructionID()
	if instrID <= 0 {
		return nil
	}
	return b.instructionsPool.View(instrID - 1)
}
