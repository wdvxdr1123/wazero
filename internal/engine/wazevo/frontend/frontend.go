// Package frontend implements the translation of WebAssembly to SSA IR using the ssa package.
package frontend

import (
	"bytes"
	"math"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa/types"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// Compiler is in charge of lowering Wasm to SSA IR, and does the optimization
// on top of it in architecture-independent way.
type Compiler struct {
	// Per-module data that is used across all functions.

	m      *wasm.Module
	offset *wazevoapi.ModuleContextOffsetData
	// ssaBuilder is a ssa.Builder used by this frontend.
	ssaBuilder             ssa.Builder
	signatures             map[*wasm.FunctionType]*types.Signature
	listenerSignatures     map[*wasm.FunctionType][2]*types.Signature
	memoryGrowSig          types.Signature
	memoryWait32Sig        types.Signature
	memoryWait64Sig        types.Signature
	memoryNotifySig        types.Signature
	checkModuleExitCodeSig types.Signature
	tableGrowSig           types.Signature
	refFuncSig             types.Signature
	memmoveSig             types.Signature
	ensureTermination      bool

	// Followings are reset by per function.

	// wasmLocalToVariable maps the index (considered as wasm.Index of locals)
	// to the corresponding ssa.Variable.
	wasmLocalToVariable                   [] /* local index to */ ssa.Variable
	wasmLocalFunctionIndex                wasm.Index
	wasmFunctionTypeIndex                 wasm.Index
	wasmFunctionTyp                       *wasm.FunctionType
	wasmFunctionLocalTypes                []wasm.ValueType
	wasmFunctionBody                      []byte
	wasmFunctionBodyOffsetInCodeSection   uint64
	memoryBaseVariable, memoryLenVariable ssa.Variable
	needMemory                            bool
	memoryShared                          bool
	globalVariables                       []ssa.Variable
	globalVariablesTypes                  []*types.Type
	mutableGlobalVariablesIndexes         []wasm.Index // index to ^.
	needListener                          bool
	needSourceOffsetInfo                  bool
	// br is reused during lowering.
	br            *bytes.Reader
	loweringState loweringState

	knownSafeBounds    [] /* ssa.ValueID to */ knownSafeBound
	knownSafeBoundsSet []ssa.ValueID

	knownSafeBoundsAtTheEndOfBlocks   [] /* ssa.BlockID to */ knownSafeBoundsAtTheEndOfBlock
	varLengthKnownSafeBoundWithIDPool wazevoapi.VarLengthPool[knownSafeBoundWithID]

	execCtxPtrValue, moduleCtxPtrValue ssa.Value

	// Following are reused for the known safe bounds analysis.

	pointers []int
	bounds   [][]knownSafeBoundWithID
}

type (
	// knownSafeBound represents a known safe bound for a value.
	knownSafeBound struct {
		// bound is a constant upper bound for the value.
		bound uint64
		// absoluteAddr is the absolute address of the value.
		absoluteAddr ssa.Value
	}
	// knownSafeBoundWithID is a knownSafeBound with the ID of the value.
	knownSafeBoundWithID struct {
		knownSafeBound
		id ssa.ValueID
	}
	knownSafeBoundsAtTheEndOfBlock = wazevoapi.VarLength[knownSafeBoundWithID]
)

var knownSafeBoundsAtTheEndOfBlockNil = wazevoapi.NewNilVarLength[knownSafeBoundWithID]()

// NewFrontendCompiler returns a frontend Compiler.
func NewFrontendCompiler(m *wasm.Module, ssaBuilder ssa.Builder, offset *wazevoapi.ModuleContextOffsetData, ensureTermination bool, listenerOn bool, sourceInfo bool) *Compiler {
	c := &Compiler{
		m:                                 m,
		ssaBuilder:                        ssaBuilder,
		br:                                bytes.NewReader(nil),
		offset:                            offset,
		ensureTermination:                 ensureTermination,
		needSourceOffsetInfo:              sourceInfo,
		varLengthKnownSafeBoundWithIDPool: wazevoapi.NewVarLengthPool[knownSafeBoundWithID](),
	}
	c.declareSignatures(listenerOn)
	return c
}

func (c *Compiler) declareSignatures(listenerOn bool) {
	m := c.m
	c.signatures = make(map[*wasm.FunctionType]*types.Signature, len(m.TypeSection)+2)
	if listenerOn {
		c.listenerSignatures = make(map[*wasm.FunctionType][2]*types.Signature, len(m.TypeSection))
	}
	for i := range m.TypeSection {
		wasmSig := &m.TypeSection[i]
		sig := SignatureForWasmFunctionType(wasmSig)
		sig.ID = types.SignatureID(i)
		c.signatures[wasmSig] = &sig
		c.ssaBuilder.DeclareSignature(&sig)

		if listenerOn {
			beforeSig, afterSig := SignatureForListener(wasmSig)
			beforeSig.ID = types.SignatureID(i) + types.SignatureID(len(m.TypeSection))
			afterSig.ID = types.SignatureID(i) + types.SignatureID(len(m.TypeSection))*2
			c.listenerSignatures[wasmSig] = [2]*types.Signature{beforeSig, afterSig}
			c.ssaBuilder.DeclareSignature(beforeSig)
			c.ssaBuilder.DeclareSignature(afterSig)
		}
	}

	begin := types.SignatureID(len(m.TypeSection))
	if listenerOn {
		begin *= 3
	}
	c.memoryGrowSig = types.Signature{
		ID: begin,
		// Takes execution context and the page size to grow.
		Params: []*types.Type{types.I64, types.I32},
		// Returns the previous page size.
		Results: []*types.Type{types.I32},
	}
	c.ssaBuilder.DeclareSignature(&c.memoryGrowSig)

	c.checkModuleExitCodeSig = types.Signature{
		ID: c.memoryGrowSig.ID + 1,
		// Only takes execution context.
		Params: []*types.Type{types.I64},
	}
	c.ssaBuilder.DeclareSignature(&c.checkModuleExitCodeSig)

	c.tableGrowSig = types.Signature{
		ID:     c.checkModuleExitCodeSig.ID + 1,
		Params: []*types.Type{types.I64 /* exec context */, types.I32 /* table index */, types.I32 /* num */, types.I64 /* ref */},
		// Returns the previous size.
		Results: []*types.Type{types.I32},
	}
	c.ssaBuilder.DeclareSignature(&c.tableGrowSig)

	c.refFuncSig = types.Signature{
		ID:     c.tableGrowSig.ID + 1,
		Params: []*types.Type{types.I64 /* exec context */, types.I32 /* func index */},
		// Returns the function reference.
		Results: []*types.Type{types.I64},
	}
	c.ssaBuilder.DeclareSignature(&c.refFuncSig)

	c.memmoveSig = types.Signature{
		ID: c.refFuncSig.ID + 1,
		// dst, src, and the byte count.
		Params: []*types.Type{types.I64, types.I64, types.I64},
	}

	c.ssaBuilder.DeclareSignature(&c.memmoveSig)

	c.memoryWait32Sig = types.Signature{
		ID: c.memmoveSig.ID + 1,
		// exec context, timeout, expected, addr
		Params: []*types.Type{types.I64, types.I64, types.I32, types.I64},
		// Returns the status.
		Results: []*types.Type{types.I32},
	}
	c.ssaBuilder.DeclareSignature(&c.memoryWait32Sig)

	c.memoryWait64Sig = types.Signature{
		ID: c.memoryWait32Sig.ID + 1,
		// exec context, timeout, expected, addr
		Params: []*types.Type{types.I64, types.I64, types.I64, types.I64},
		// Returns the status.
		Results: []*types.Type{types.I32},
	}
	c.ssaBuilder.DeclareSignature(&c.memoryWait64Sig)

	c.memoryNotifySig = types.Signature{
		ID: c.memoryWait64Sig.ID + 1,
		// exec context, count, addr
		Params: []*types.Type{types.I64, types.I32, types.I64},
		// Returns the number notified.
		Results: []*types.Type{types.I32},
	}
	c.ssaBuilder.DeclareSignature(&c.memoryNotifySig)
}

// SignatureForWasmFunctionType returns the types.Signature for the given wasm.FunctionType.
func SignatureForWasmFunctionType(typ *wasm.FunctionType) types.Signature {
	sig := types.Signature{
		// +2 to pass moduleContextPtr and executionContextPtr. See the inline comment LowerToSSA.
		Params:  make([]*types.Type, len(typ.Params)+2),
		Results: make([]*types.Type, len(typ.Results)),
	}
	sig.Params[0] = executionContextPtrTyp
	sig.Params[1] = moduleContextPtrTyp
	for j, typ := range typ.Params {
		sig.Params[j+2] = WasmTypeToSSAType(typ)
	}
	for j, typ := range typ.Results {
		sig.Results[j] = WasmTypeToSSAType(typ)
	}
	return sig
}

// Init initializes the state of frontendCompiler and make it ready for a next function.
func (c *Compiler) Init(idx, typIndex wasm.Index, typ *wasm.FunctionType, localTypes []wasm.ValueType, body []byte, needListener bool, bodyOffsetInCodeSection uint64) {
	c.ssaBuilder.Init(c.signatures[typ])
	c.loweringState.reset()

	c.wasmFunctionTypeIndex = typIndex
	c.wasmLocalFunctionIndex = idx
	c.wasmFunctionTyp = typ
	c.wasmFunctionLocalTypes = localTypes
	c.wasmFunctionBody = body
	c.wasmFunctionBodyOffsetInCodeSection = bodyOffsetInCodeSection
	c.needListener = needListener
	c.clearSafeBounds()
	c.varLengthKnownSafeBoundWithIDPool.Reset()
	c.knownSafeBoundsAtTheEndOfBlocks = c.knownSafeBoundsAtTheEndOfBlocks[:0]
}

// Note: this assumes 64-bit platform (I believe we won't have 32-bit backend ;)).
var executionContextPtrTyp, moduleContextPtrTyp = types.I64, types.I64

// LowerToSSA lowers the current function to SSA function which will be held by ssaBuilder.
// After calling this, the caller will be able to access the SSA info in *Compiler.ssaBuilder.
//
// Note that this only does the naive lowering, and do not do any optimization, instead the caller is expected to do so.
func (c *Compiler) LowerToSSA() {
	builder := c.ssaBuilder

	// Set up the entry block.
	entryBlock := builder.AllocateBasicBlock()
	builder.SetCurrentBlock(entryBlock)

	// Functions always take two parameters in addition to Wasm-level parameters:
	//
	//  1. executionContextPtr: pointer to the *executionContext in wazevo package.
	//    This will be used to exit the execution in the face of trap, plus used for host function calls.
	//
	// 	2. moduleContextPtr: pointer to the *moduleContextOpaque in wazevo package.
	//	  This will be used to access memory, etc. Also, this will be used during host function calls.
	//
	// Note: it's clear that sometimes a function won't need them. For example,
	//  if the function doesn't trap and doesn't make function call, then
	// 	we might be able to eliminate the parameter. However, if that function
	//	can be called via call_indirect, then we cannot eliminate because the
	//  signature won't match with the expected one.
	// TODO: maybe there's some way to do this optimization without glitches, but so far I have no clue about the feasibility.
	//
	// Note: In Wasmtime or many other runtimes, moduleContextPtr is called "vmContext". Also note that `moduleContextPtr`
	//  is wazero-specific since other runtimes can naturally use the OS-level signal to do this job thanks to the fact that
	//  they can use native stack vs wazero cannot use Go-routine stack and have to use Go-runtime allocated []byte as a stack.
	c.execCtxPtrValue = entryBlock.AddParam(builder, executionContextPtrTyp)
	c.moduleCtxPtrValue = entryBlock.AddParam(builder, moduleContextPtrTyp)
	builder.AnnotateValue(c.execCtxPtrValue, "exec_ctx")
	builder.AnnotateValue(c.moduleCtxPtrValue, "module_ctx")

	for i, typ := range c.wasmFunctionTyp.Params {
		st := WasmTypeToSSAType(typ)
		variable := builder.DeclareVariable(st)
		value := entryBlock.AddParam(builder, st)
		builder.DefineVariable(variable, value, entryBlock)
		c.setWasmLocalVariable(wasm.Index(i), variable)
	}
	c.declareWasmLocals()
	c.declareNecessaryVariables()

	c.lowerBody(entryBlock)
}

// localVariable returns the SSA variable for the given Wasm local index.
func (c *Compiler) localVariable(index wasm.Index) ssa.Variable {
	return c.wasmLocalToVariable[index]
}

func (c *Compiler) setWasmLocalVariable(index wasm.Index, variable ssa.Variable) {
	idx := int(index)
	if idx >= len(c.wasmLocalToVariable) {
		c.wasmLocalToVariable = append(c.wasmLocalToVariable, make([]ssa.Variable, idx+1-len(c.wasmLocalToVariable))...)
	}
	c.wasmLocalToVariable[idx] = variable
}

// declareWasmLocals declares the SSA variables for the Wasm locals.
func (c *Compiler) declareWasmLocals() {
	localCount := wasm.Index(len(c.wasmFunctionTyp.Params))
	for i, typ := range c.wasmFunctionLocalTypes {
		st := WasmTypeToSSAType(typ)
		variable := c.ssaBuilder.DeclareVariable(st)
		c.setWasmLocalVariable(wasm.Index(i)+localCount, variable)
		c.ssaBuilder.InsertZeroValue(st)
	}
}

func (c *Compiler) declareNecessaryVariables() {
	if c.needMemory = c.m.MemorySection != nil; c.needMemory {
		c.memoryShared = c.m.MemorySection.IsShared
	} else if c.needMemory = c.m.ImportMemoryCount > 0; c.needMemory {
		for _, imp := range c.m.ImportSection {
			if imp.Type == wasm.ExternTypeMemory {
				c.memoryShared = imp.DescMem.IsShared
				break
			}
		}
	}

	if c.needMemory {
		c.memoryBaseVariable = c.ssaBuilder.DeclareVariable(types.I64)
		c.memoryLenVariable = c.ssaBuilder.DeclareVariable(types.I64)
	}

	c.globalVariables = c.globalVariables[:0]
	c.mutableGlobalVariablesIndexes = c.mutableGlobalVariablesIndexes[:0]
	c.globalVariablesTypes = c.globalVariablesTypes[:0]
	for _, imp := range c.m.ImportSection {
		if imp.Type == wasm.ExternTypeGlobal {
			desc := imp.DescGlobal
			c.declareWasmGlobal(desc.ValType, desc.Mutable)
		}
	}
	for _, g := range c.m.GlobalSection {
		desc := g.Type
		c.declareWasmGlobal(desc.ValType, desc.Mutable)
	}

	// TODO: add tables.
}

func (c *Compiler) declareWasmGlobal(typ wasm.ValueType, mutable bool) {
	var st *types.Type
	switch typ {
	case wasm.ValueTypeI32:
		st = types.I32
	case wasm.ValueTypeI64,
		// Both externref and funcref are represented as I64 since we only support 64-bit platforms.
		wasm.ValueTypeExternref, wasm.ValueTypeFuncref:
		st = types.I64
	case wasm.ValueTypeF32:
		st = types.F32
	case wasm.ValueTypeF64:
		st = types.F64
	case wasm.ValueTypeV128:
		st = types.V128
	default:
		panic("TODO: " + wasm.ValueTypeName(typ))
	}
	v := c.ssaBuilder.DeclareVariable(st)
	index := wasm.Index(len(c.globalVariables))
	c.globalVariables = append(c.globalVariables, v)
	c.globalVariablesTypes = append(c.globalVariablesTypes, st)
	if mutable {
		c.mutableGlobalVariablesIndexes = append(c.mutableGlobalVariablesIndexes, index)
	}
}

// WasmTypeToSSAType converts wasm.ValueType to *types.Type.
func WasmTypeToSSAType(vt wasm.ValueType) *types.Type {
	switch vt {
	case wasm.ValueTypeI32:
		return types.I32
	case wasm.ValueTypeI64,
		// Both externref and funcref are represented as I64 since we only support 64-bit platforms.
		wasm.ValueTypeExternref, wasm.ValueTypeFuncref:
		return types.I64
	case wasm.ValueTypeF32:
		return types.F32
	case wasm.ValueTypeF64:
		return types.F64
	case wasm.ValueTypeV128:
		return types.V128
	default:
		panic("TODO: " + wasm.ValueTypeName(vt))
	}
}

// addBlockParamsFromWasmTypes adds the block parameters to the given block.
func (c *Compiler) addBlockParamsFromWasmTypes(tps []wasm.ValueType, blk *ssa.BasicBlock) {
	for _, typ := range tps {
		st := WasmTypeToSSAType(typ)
		blk.AddParam(c.ssaBuilder, st)
	}
}

// formatBuilder outputs the constructed SSA function as a string with a source information.
func (c *Compiler) formatBuilder() string {
	return c.ssaBuilder.Format()
}

// SignatureForListener returns the signatures for the listener functions.
func SignatureForListener(wasmSig *wasm.FunctionType) (*types.Signature, *types.Signature) {
	beforeSig := &types.Signature{}
	beforeSig.Params = make([]*types.Type, len(wasmSig.Params)+2)
	beforeSig.Params[0] = types.I64 // Execution context.
	beforeSig.Params[1] = types.I32 // Function index.
	for i, p := range wasmSig.Params {
		beforeSig.Params[i+2] = WasmTypeToSSAType(p)
	}
	afterSig := &types.Signature{}
	afterSig.Params = make([]*types.Type, len(wasmSig.Results)+2)
	afterSig.Params[0] = types.I64 // Execution context.
	afterSig.Params[1] = types.I32 // Function index.
	for i, p := range wasmSig.Results {
		afterSig.Params[i+2] = WasmTypeToSSAType(p)
	}
	return beforeSig, afterSig
}

// isBoundSafe returns true if the given value is known to be safe to access up to the given bound.
func (c *Compiler) getKnownSafeBound(v ssa.ValueID) *knownSafeBound {
	if int(v) >= len(c.knownSafeBounds) {
		return nil
	}
	return &c.knownSafeBounds[v]
}

// recordKnownSafeBound records the given safe bound for the given value.
func (c *Compiler) recordKnownSafeBound(v ssa.ValueID, safeBound uint64, absoluteAddr ssa.Value) {
	if int(v) >= len(c.knownSafeBounds) {
		c.knownSafeBounds = append(c.knownSafeBounds, make([]knownSafeBound, v+1)...)
	}

	if exiting := c.knownSafeBounds[v]; exiting.bound == 0 {
		c.knownSafeBounds[v] = knownSafeBound{
			bound:        safeBound,
			absoluteAddr: absoluteAddr,
		}
		c.knownSafeBoundsSet = append(c.knownSafeBoundsSet, v)
	} else if safeBound > exiting.bound {
		c.knownSafeBounds[v].bound = safeBound
	}
}

// clearSafeBounds clears the known safe bounds.
func (c *Compiler) clearSafeBounds() {
	for _, v := range c.knownSafeBoundsSet {
		ptr := &c.knownSafeBounds[v]
		ptr.bound = 0
		ptr.absoluteAddr = ssa.ValueInvalid
	}
	c.knownSafeBoundsSet = c.knownSafeBoundsSet[:0]
}

// resetAbsoluteAddressInSafeBounds resets the absolute addresses recorded in the known safe bounds.
func (c *Compiler) resetAbsoluteAddressInSafeBounds() {
	for _, v := range c.knownSafeBoundsSet {
		ptr := &c.knownSafeBounds[v]
		ptr.absoluteAddr = ssa.ValueInvalid
	}
}

func (k *knownSafeBound) valid() bool {
	return k != nil && k.bound > 0
}

func (c *Compiler) finalizeKnownSafeBoundsAtTheEndOfBlock(bID ssa.BasicBlockID) {
	_bID := int(bID)
	if l := len(c.knownSafeBoundsAtTheEndOfBlocks); _bID >= l {
		c.knownSafeBoundsAtTheEndOfBlocks = append(c.knownSafeBoundsAtTheEndOfBlocks,
			make([]knownSafeBoundsAtTheEndOfBlock, _bID+1-len(c.knownSafeBoundsAtTheEndOfBlocks))...)
		for i := l; i < len(c.knownSafeBoundsAtTheEndOfBlocks); i++ {
			c.knownSafeBoundsAtTheEndOfBlocks[i] = knownSafeBoundsAtTheEndOfBlockNil
		}
	}
	p := &c.varLengthKnownSafeBoundWithIDPool
	size := len(c.knownSafeBoundsSet)
	allocated := c.varLengthKnownSafeBoundWithIDPool.Allocate(size)
	// Sort the known safe bounds by the value ID so that we can use the intersection algorithm in initializeCurrentBlockKnownBounds.
	sortSSAValueIDs(c.knownSafeBoundsSet)
	for _, vID := range c.knownSafeBoundsSet {
		kb := c.knownSafeBounds[vID]
		allocated = allocated.Append(p, knownSafeBoundWithID{
			knownSafeBound: kb,
			id:             vID,
		})
	}
	c.knownSafeBoundsAtTheEndOfBlocks[bID] = allocated
	c.clearSafeBounds()
}

func (c *Compiler) initializeCurrentBlockKnownBounds() {
	currentBlk := c.ssaBuilder.CurrentBlock()
	switch preds := len(currentBlk.Pred); preds {
	case 0:
	case 1:
		pred := currentBlk.Pred[0].ID()
		for _, kb := range c.getKnownSafeBoundsAtTheEndOfBlocks(pred).View() {
			// Unless the block is sealed, we cannot assume the absolute address is valid:
			// later we might add another predecessor that has no visibility of that value.
			addr := ssa.ValueInvalid
			if currentBlk.Sealed() {
				addr = kb.absoluteAddr
			}
			c.recordKnownSafeBound(kb.id, kb.bound, addr)
		}
	default:
		c.pointers = c.pointers[:0]
		c.bounds = c.bounds[:0]
		for i := 0; i < preds; i++ {
			c.bounds = append(c.bounds, c.getKnownSafeBoundsAtTheEndOfBlocks(currentBlk.Pred[i].ID()).View())
			c.pointers = append(c.pointers, 0)
		}

		// If there are multiple predecessors, we need to find the intersection of the known safe bounds.

	outer:
		for {
			smallestID := ssa.ValueID(math.MaxUint32)
			for i, ptr := range c.pointers {
				if ptr >= len(c.bounds[i]) {
					break outer
				}
				cb := &c.bounds[i][ptr]
				if id := cb.id; id < smallestID {
					smallestID = cb.id
				}
			}

			// Check if current elements are the same across all lists.
			same := true
			minBound := uint64(math.MaxUint64)
			for i := 0; i < preds; i++ {
				cb := &c.bounds[i][c.pointers[i]]
				if cb.id != smallestID {
					same = false
				} else {
					if cb.bound < minBound {
						minBound = cb.bound
					}
					c.pointers[i]++
				}
			}

			if same { // All elements are the same.
				// Absolute address cannot be used in the intersection since the value might be only defined in one of the predecessors.
				c.recordKnownSafeBound(smallestID, minBound, ssa.ValueInvalid)
			}
		}
	}
}

func (c *Compiler) getKnownSafeBoundsAtTheEndOfBlocks(id ssa.BasicBlockID) knownSafeBoundsAtTheEndOfBlock {
	if int(id) >= len(c.knownSafeBoundsAtTheEndOfBlocks) {
		return knownSafeBoundsAtTheEndOfBlockNil
	}
	return c.knownSafeBoundsAtTheEndOfBlocks[id]
}
