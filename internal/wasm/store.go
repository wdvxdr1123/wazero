package internalwasm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"reflect"
	"sync"

	"github.com/tetratelabs/wazero/internal/ieee754"
	"github.com/tetratelabs/wazero/internal/leb128"
	publicwasm "github.com/tetratelabs/wazero/wasm"
)

type (
	// Store is the runtime representation of "instantiated" Wasm module and objects.
	// Multiple modules can be instantiated within a single store, and each instance,
	// (e.g. function instance) can be referenced by other module instances in a Store via Module.ImportSection.
	//
	// Every type whose name ends with "Instance" suffix belongs to exactly one store.
	//
	// Note that store is not thread (concurrency) safe, meaning that using single Store
	// via multiple goroutines might result in race conditions. In that case, the invocation
	// and access to any methods and field of Store must be guarded by mutex.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#store%E2%91%A0
	Store struct {
		// The following fields are wazero-specific fields of Store.

		// ctx is the default context used for function calls
		ctx context.Context

		// Engine is a global context for a Store which is in responsible for compilation and execution of Wasm modules.
		Engine Engine

		// ModuleInstances holds the instantiated Wasm modules by module name from Instantiate.
		ModuleInstances map[string]*ModuleInstance

		// hostExports holds host functions by module name from ExportHostFunctions.
		hostExports map[string]*HostExports

		// ModuleContexts holds default host function call contexts keyed by module name.
		ModuleContexts map[string]*ModuleContext

		// TypeIDs maps each FunctionType.String() to a unique FunctionTypeID. This is used at runtime to
		// do type-checks on indirect function calls.
		TypeIDs map[string]FunctionTypeID

		// maximumFunctionAddress represents the limit on the number of function addresses (= function instances) in a store.
		// Note: this is fixed to 2^27 but have this a field for testability.
		maximumFunctionAddress FunctionAddress
		//  maximumFunctionTypes represents the limit on the number of function types in a store.
		// Note: this is fixed to 2^27 but have this a field for testability.
		maximumFunctionTypes int

		releasedFunctionAddress []FunctionAddress
		releasedMemoryAddress   []memoryAddress
		releasedTableAddress    []tableAddress
		releasedGlobalAddress   []globalAddress

		// The followings fields match the definition of Store in the specification.

		// Functions holds function instances (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#function-instances%E2%91%A0),
		// in this store.
		// The slice index is to be interpreted as funcaddr (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-funcaddr).
		Functions []*FunctionInstance
		// Globals holds global instances (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#global-instances%E2%91%A0),
		// in this store.
		// The slice index is to be interpreted as globaladdr (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-globaladdr).
		Globals []*GlobalInstance
		// Memories holds memory instances (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#memory-instances%E2%91%A0),
		// in this store.
		// The slice index is to be interpreted as memaddr (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-memaddr).
		Memories []*MemoryInstance
		// Tables holds table instances (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#table-instances%E2%91%A0),
		// in this store.
		// The slice index is to be interpreted as tableaddr (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-tableaddr).
		Tables []*TableInstance

		mux sync.Mutex
	}

	// ModuleInstance represents instantiated wasm module.
	// The difference from the spec is that in wazero, a ModuleInstance holds pointers
	// to the instances, rather than "addresses" (i.e. index to Store.Functions, Globals, etc) for convenience.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-moduleinst
	ModuleInstance struct {
		Name      string
		Exports   map[string]*ExportInstance
		Functions []*FunctionInstance
		Globals   []*GlobalInstance
		// MemoryInstance is set when Module.MemorySection had a memory, regardless of whether it was exported.
		// Note: This avoids the name "Memory" which is an interface method name.
		MemoryInstance *MemoryInstance
		Tables         []*TableInstance
		Types          []*TypeInstance

		// TODO
		refCount        referenceCounter
		importedModules map[*ModuleInstance]struct{}
	}

	// ExportInstance represents an exported instance in a Store.
	// The difference from the spec is that in wazero, a ExportInstance holds pointers
	// to the instances, rather than "addresses" (i.e. index to Store.Functions, Globals, etc) for convenience.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-exportinst
	ExportInstance struct {
		Type     ExternType
		Function *FunctionInstance
		Global   *GlobalInstance
		Memory   *MemoryInstance
		Table    *TableInstance
	}

	// FunctionInstance represents a function instance in a Store.
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#function-instances%E2%91%A0
	FunctionInstance struct {
		// ModuleInstance holds the pointer to the module instance to which this function belongs.
		ModuleInstance *ModuleInstance
		// Body is the function body in WebAssembly Binary Format
		Body []byte
		// FunctionType holds the pointer to TypeInstance whose functionType field equals that of this function.
		FunctionType *TypeInstance
		// LocalTypes holds types of locals.
		LocalTypes []ValueType
		// FunctionKind describes how this function should be called.
		FunctionKind FunctionKind
		// HostFunction holds the runtime representation of host functions.
		// This is nil when FunctionKind == FunctionKindWasm. Otherwise, all the above fields are ignored as they are
		// specific to Wasm functions.
		HostFunction *reflect.Value
		// Address is the funcaddr(https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-funcaddr) of this function instance.
		// More precisely, this equals the index of this function instance in store.Functions.
		// All function calls are made via funcaddr at runtime, not the index (scoped to a module).
		//
		// This is used by both host and non-host functions.
		Address FunctionAddress
		// Name is for debugging purpose, and is used to argument the stack traces.
		//
		// When HostFunction is not nil, this returns dot-delimited parameters given to
		// Store.AddHostFunction. Ex. something.realistic
		//
		// Otherwise, this is the corresponding value in NameSection.FunctionNames or "unknown" if unavailable.
		Name string
	}

	// TypeInstance is a store-specific representation of FunctionType where the function type
	// is coupled with TypeID which is specific in a store.
	TypeInstance struct {
		Type *FunctionType
		// TypeID is assigned by a store for FunctionType.
		TypeID FunctionTypeID
	}

	// GlobalInstance represents a global instance in a store.
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#global-instances%E2%91%A0
	GlobalInstance struct {
		Type *GlobalType
		// Val holds a 64-bit representation of the actual value.
		Val uint64

		// address is the globaladdr(https://www.w3.org/TR/wasm-core-1/#syntax-globaladdr) of this global instance.
		// In other words, this equals the index of this global instance in store.Globals.
		address globalAddress
	}

	// TableInstance represents a table instance in a store.
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#table-instances%E2%91%A0
	//
	// Note this is fixed to function type until post 20191205 reference type is implemented.
	TableInstance struct {
		// Table holds the table elements managed by this table instance.
		//
		// Note: we intentionally use "[]TableElement", not "[]*TableElement",
		// because the JIT Engine accesses this slice directly from assembly.
		// If pointer type is used, the access becomes two level indirection (two hops of pointer jumps)
		// which is a bit costly. TableElement is 96 bit (32 and 64 bit fields) so the cost of using value type
		// would be ignorable.
		Table []TableElement
		Min   uint32
		Max   *uint32
		// Currently fixed to 0x70 (funcref type).
		ElemType byte

		// address is the tableaddr(https://www.w3.org/TR/wasm-core-1/#syntax-tableaddr) of this table instance.
		// In other words, this equals the index of this table instance in store.Tables.
		address tableAddress
	}

	// TableElement represents an item in a table instance.
	//
	// Note: this is fixed to function type as it is the only supported type in WebAssembly 1.0 (20191205)
	TableElement struct {
		// FunctionAddress is funcaddr (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-funcaddr)
		// of the target function instance. More precisely, this equals the index of
		// the target function instance in Store.FunctionInstances.
		FunctionAddress FunctionAddress
		// FunctionTypeID is the type ID of the target function's type, which
		// equals store.Functions[FunctionAddress].FunctionType.TypeID.
		FunctionTypeID FunctionTypeID
	}

	// MemoryInstance represents a memory instance in a store, and implements wasm.Memory.
	//
	// Note: In WebAssembly 1.0 (20191205), there may be up to one Memory per store, which means the precise memory is always
	// wasm.Store Memories index zero: `store.Memories[0]`
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#memory-instances%E2%91%A0.
	MemoryInstance struct {
		Buffer []byte
		Min    uint32
		Max    *uint32

		// address is the memoryaddr(https://www.w3.org/TR/wasm-core-1/#syntax-tableaddr) of this memory instance.
		// In other words, this equals the index of this memory instance in store.Memories.
		address memoryAddress
	}

	// FunctionAddress is funcaddr (https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-funcaddr),
	// and the index to Store.Functions.
	FunctionAddress uint64
	// memoryAddress is memaddr (https://www.w3.org/TR/wasm-core-1/#syntax-memaddr),
	// and the index to Store.Functions.
	memoryAddress uint64
	// globalAddress is memaddr (https://www.w3.org/TR/wasm-core-1/#syntax-globaladdr),
	// and the index to Store.Globals.
	globalAddress uint64
	// tableAddress is tableaddr (https://www.w3.org/TR/wasm-core-1/#syntax-tableaddr),
	// and the index to Store.Tables.
	tableAddress uint64

	// FunctionTypeID is a uniquely assigned integer for a function type.
	// This is wazero specific runtime object and specific to a store,
	// and used at runtime to do type-checks on indirect function calls.
	FunctionTypeID uint32
)

// The wazero specific limitations described at RATIONALE.md.
const (
	maximumFunctionAddress = 1 << 27
	maximumFunctionTypes   = 1 << 27
)

// addExport adds and indexes the given export or errs if the name is already exported.
func (m *ModuleInstance) addExport(name string, e *ExportInstance) error {
	if _, ok := m.Exports[name]; ok {
		return fmt.Errorf("%q is already exported in module %q", name, m.Name)
	}
	m.Exports[name] = e
	return nil
}

// GetExport returns an export of the given name and type or errs if not exported or the wrong type.
func (m *ModuleInstance) GetExport(name string, et ExternType) (*ExportInstance, error) {
	exp, ok := m.Exports[name]
	if !ok {
		return nil, fmt.Errorf("%q is not exported in module %q", name, m.Name)
	}
	if exp.Type != et {
		return nil, fmt.Errorf("export %q in module %q is a %s, not a %s", name, m.Name, ExternTypeName(exp.Type), ExternTypeName(et))
	}
	return exp, nil
}

func NewStore(ctx context.Context, engine Engine) *Store {
	return &Store{
		ctx:                    ctx,
		ModuleInstances:        map[string]*ModuleInstance{},
		ModuleContexts:         map[string]*ModuleContext{},
		TypeIDs:                map[string]FunctionTypeID{},
		Engine:                 engine,
		maximumFunctionAddress: maximumFunctionAddress,
		maximumFunctionTypes:   maximumFunctionTypes,
	}
}

// checkFuncAddrOverflow checks if there would be too many function instantces in a store.
func (s *Store) checkFuncAddrOverflow(newInstanceNum int) error {
	if len(s.Functions)+newInstanceNum > int(s.maximumFunctionAddress) {
		return fmt.Errorf("too many functions in a store")
	}
	return nil
}

func (s *Store) Instantiate(module *Module, name string) (*ModuleExports, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if err := s.requireModuleUnused(name); err != nil {
		return nil, err
	}

	// Check if there would be too many function instantces in a store.
	if err := s.checkFuncAddrOverflow(len(module.FunctionSection)); err != nil {
		return nil, err
	}

	importedFunctions, importedGlobals, importedTables, importedMemory, importedModules, err := s.resolveImports(module)
	if err != nil {
		return nil, err
	}

	types, err := s.getTypeInstances(module.TypeSection)
	if err != nil {
		return nil, err
	}

	functions, globals, tables, memory := module.buildInstances()
	instance := newModuleInstance(name, importedFunctions, functions, importedGlobals,
		globals, importedTables, tables, importedMemory, memory, types, importedModules)

	if err = instance.validateElements(module); err != nil {
		return nil, err
	}

	if instance.validateData(module); err != nil {
		return nil, err
	}

	// Now we are ready to compile functions.
	s.addFunctionInstances(functions...) // Need to assign funcaddr to each instance before compilation.
	for i, f := range functions {
		if err := s.Engine.Compile(f); err != nil {
			idx := module.SectionElementCount(SectionIDFunction) - 1
			// On the failure, release the assigned funcaddr for futur uses.
			if err := s.releaseFunctionInstances(functions...); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("compilation failed at index %d/%d: %w", i, idx, err)
		}
	}

	// Now all the validation passes, we are safe to mutate store and memory/table instances (possibly imported ones).
	instance.applyElements(module.ElementSection)
	instance.applyData(module.DataSection)

	// Also, persist the instances other than functions (which is already persisted before compilation).
	s.addGlobalInstances(globals...)
	s.addTableInstances(tables...)
	s.addMemoryInstance(instance.MemoryInstance)

	// Build the default context for calls to this module.
	modCtx := NewModuleContext(s.ctx, s.Engine, instance)
	s.ModuleContexts[instance.Name] = modCtx
	s.ModuleInstances[instance.Name] = instance

	// Execute the start function.
	if module.StartSection != nil {
		funcIdx := *module.StartSection
		if _, err := s.Engine.Call(modCtx, instance.Functions[funcIdx]); err != nil {
			return nil, fmt.Errorf("module[%s] start function failed: %w", name, err)
		}
	}

	instance.buildExportInstances(module)
	return &ModuleExports{s, modCtx}, nil
}

func newModuleInstance(name string, importedFunctions, functions []*FunctionInstance,
	importedGlobals, globals []*GlobalInstance, importedTables, tables []*TableInstance,
	memory, importedMemory *MemoryInstance, typeInstances []*TypeInstance, importedModules map[*ModuleInstance]struct{}) *ModuleInstance {

	inst := &ModuleInstance{Name: name, Types: typeInstances, importedModules: importedModules}

	inst.Functions = append(inst.Functions, importedFunctions...)
	for i, f := range functions {
		f.FunctionType = typeInstances[i]
		f.ModuleInstance = inst
		// TODO: name.
	}

	inst.Globals = append(inst.Globals, importedGlobals...)
	inst.Globals = append(inst.Globals, globals...)

	inst.Tables = append(inst.Tables, importedTables...)
	inst.Tables = append(inst.Tables, tables...)

	if importedMemory != nil {
		inst.MemoryInstance = importedMemory
	} else {
		inst.MemoryInstance = memory
	}
	return inst
}

func (s *Store) ReleaseModuleInstance(instance *ModuleInstance) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	for importingMod := range instance.importedModules {
		if count := importingMod.refCount.dec(); count == 0 {
			s.ReleaseModuleInstance(importingMod)
		}
	}

	if count := instance.refCount.dec(); count > 0 {
		// This case other modules are importing this module instance and still alive.
		return nil
	}

	if err := s.releaseFunctionInstances(instance.Functions...); err != nil {
		return fmt.Errorf("unable to release function instance: %w", err)
	}
	s.releaseMemoryInstance(instance.MemoryInstance)
	s.releaseTableInstances(instance.Tables...)
	s.releaseGlobalInstances(instance.Globals...)

	// Explicitly assign nil so that we ensure this moduleInstance no longer holds reference to instances.
	instance.Exports = nil
	instance.Globals = nil
	instance.Functions = nil
	instance.Tables = nil
	instance.Types = nil

	s.ModuleContexts[instance.Name] = nil
	s.ModuleInstances[instance.Name] = nil
	return nil
}

func (s *Store) releaseFunctionInstances(fs ...*FunctionInstance) error {
	for _, f := range fs {
		if err := s.Engine.Release(f); err != nil {
			return err
		}

		// Release refernce to the function instance.
		s.Functions[f.Address] = nil

		// Append the address so that we can reuse it in order to avoid address space explosion.
		s.releasedFunctionAddress = append(s.releasedFunctionAddress, f.Address)
	}
	return nil
}

func (s *Store) addFunctionInstances(fs ...*FunctionInstance) {
	for _, f := range fs {
		var addr FunctionAddress
		if len(s.releasedFunctionAddress) > 0 {
			id := len(s.releasedTableAddress) - 1
			// Pop one address from releasedFunctionAddress slice.
			addr, s.releasedFunctionAddress = s.releasedFunctionAddress[id], s.releasedFunctionAddress[:id]
			s.Functions[f.Address] = f
		} else {
			addr = FunctionAddress(len(s.Functions))
			s.Functions = append(s.Functions, f)
		}
		f.Address = addr
	}

}

func (s *Store) releaseGlobalInstances(gs ...*GlobalInstance) {
	for _, g := range gs {
		// Release refernce to the global instance.
		s.Globals[g.address] = nil

		// Append the address so that we can reuse it in order to avoid address space explosion.
		s.releasedGlobalAddress = append(s.releasedGlobalAddress, g.address)
	}
}

func (s *Store) addGlobalInstances(gs ...*GlobalInstance) {
	for _, g := range gs {
		var addr globalAddress
		if len(s.releasedGlobalAddress) > 0 {
			id := len(s.releasedTableAddress) - 1
			// Pop one address from releasedGlobalAddress slice.
			addr, s.releasedGlobalAddress = s.releasedGlobalAddress[id], s.releasedGlobalAddress[:id]
			s.Globals[g.address] = g
		} else {
			addr = globalAddress(len(s.Globals))
			s.Globals = append(s.Globals, g)
		}
		g.address = addr
	}
}

func (s *Store) releaseTableInstances(ts ...*TableInstance) {
	for _, t := range ts {
		// Release refernce to the table instance.
		s.Tables[t.address] = nil

		// Append the address so that we can reuse it in order to avoid address space explosion.
		s.releasedTableAddress = append(s.releasedTableAddress, t.address)
	}
}

func (s *Store) addTableInstances(ts ...*TableInstance) {
	for _, t := range ts {
		var addr tableAddress
		if len(s.releasedTableAddress) > 0 {
			id := len(s.releasedTableAddress) - 1
			// Pop one address from releasedTableAddress slice.
			addr, s.releasedTableAddress = s.releasedTableAddress[id], s.releasedTableAddress[:id]
			s.Tables[addr] = t
		} else {
			addr = tableAddress(len(s.Tables))
			s.Tables = append(s.Tables, t)
		}
		t.address = addr
	}
}

func (s *Store) releaseMemoryInstance(m *MemoryInstance) {
	// Release refernce to the memory instance.
	s.Memories[m.address] = nil

	// Append the address so that we can reuse it in order to avoid address space explosion.
	s.releasedMemoryAddress = append(s.releasedMemoryAddress, m.address)
}

func (s *Store) addMemoryInstance(m *MemoryInstance) {
	if m == nil {
		return
	}

	var addr memoryAddress
	if len(s.releasedMemoryAddress) > 0 {
		id := len(s.releasedMemoryAddress) - 1
		// Pop one address from releasedMemoryAddress slice.
		addr, s.releasedMemoryAddress = s.releasedMemoryAddress[id], s.releasedMemoryAddress[:id]
		s.Memories[addr] = m
	} else {
		addr = memoryAddress(len(s.Memories))
		s.Memories = append(s.Memories, m)
	}
	m.address = addr
}

// ModuleExports implements wasm.Store ModuleExports
func (s *Store) ModuleExports(moduleName string) publicwasm.ModuleExports {
	if m, ok := s.ModuleContexts[moduleName]; !ok {
		return nil
	} else {
		return &ModuleExports{s, m}
	}
}

// ModuleExports implements wasm.ModuleExports
type ModuleExports struct {
	s *Store
	// Context is exported for /wasi.go
	Context *ModuleContext
}

// Function implements wasm.ModuleExports Function
func (m *ModuleExports) Function(name string) publicwasm.Function {
	exp, err := m.Context.Module.GetExport(name, ExternTypeFunc)
	if err != nil {
		return nil
	}
	return &exportedFunction{module: m.Context, function: exp.Function}
}

// Memory implements wasm.ModuleExports Memory
func (m *ModuleExports) Memory(name string) publicwasm.Memory {
	exp, err := m.Context.Module.GetExport(name, ExternTypeMemory)
	if err != nil {
		return nil
	}
	return exp.Memory
}

// HostExports implements wasm.Store HostExports
func (s *Store) HostExports(moduleName string) publicwasm.HostExports {
	return s.hostExports[moduleName]
}

func (s *Store) getExport(moduleName string, name string, et ExternType) (exp *ExportInstance, err error) {
	if m, ok := s.ModuleInstances[moduleName]; !ok {
		return nil, fmt.Errorf("module %s not instantiated", moduleName)
	} else if exp, err = m.GetExport(name, et); err != nil {
		return
	}
	return
}

func (s *Store) resolveImports(module *Module) (
	functions []*FunctionInstance, globals []*GlobalInstance,
	tables []*TableInstance, memory *MemoryInstance,
	importedModules map[*ModuleInstance]struct{},
	err error,
) {

	s.mux.Lock()
	defer s.mux.Unlock()

	importedModules = map[*ModuleInstance]struct{}{}
	for _, is := range module.ImportSection {
		m, ok := s.ModuleInstances[is.Module]
		if !ok {
			err = fmt.Errorf("module %s not instantiated", is.Module)
			return
		}

		// Note: at this point we don't increase the ref count.
		importedModules[m] = struct{}{}

		var exp *ExportInstance
		exp, err = m.GetExport(is.Module, is.Type)
		if err != nil {
			return
		}

		switch is.Type {
		case ExternTypeFunc:
			typeIndex := is.DescFunc
			if int(typeIndex) >= len(m.Types) {
				err = fmt.Errorf("unknown type for function import")
				return
			}
			expectedType := m.Types[typeIndex].Type
			f := exp.Function
			if !bytes.Equal(expectedType.Results, f.FunctionType.Type.Results) {
				err = fmt.Errorf("return signature mimatch: %#x != %#x", expectedType.Results, f.FunctionType.Type.Results)
				return
			} else if !bytes.Equal(expectedType.Params, f.FunctionType.Type.Params) {
				err = fmt.Errorf("input signature mimatch: %#x != %#x", expectedType.Params, f.FunctionType.Type.Params)
				return
			}
			functions = append(functions, f)
		case ExternTypeTable:
			tableType := is.DescTable
			table := exp.Table
			if tableType == nil {
				err = fmt.Errorf("table type is invalid")
				return
			}
			if table.ElemType != tableType.ElemType {
				err = fmt.Errorf("incompatible table imports: element type mismatch")
				return
			}
			if table.Min < tableType.Limit.Min {
				err = fmt.Errorf("incompatible table imports: minimum size mismatch")
				return
			}

			if tableType.Limit.Max != nil {
				if table.Max == nil {
					err = fmt.Errorf("incompatible table imports: maximum size mismatch")
					return
				} else if *table.Max > *tableType.Limit.Max {
					err = fmt.Errorf("incompatible table imports: maximum size mismatch")
					return
				}
			}
			tables = append(tables, table)
		case ExternTypeMemory:
			memoryType := is.DescMem
			if memoryType == nil {
				err = fmt.Errorf("memory type is invalid")
				return
			}
			memory = exp.Memory
			if memory.Min < memoryType.Min {
				err = fmt.Errorf("incompatible memory imports: minimum size mismatch")
				return
			}
			if memoryType.Max != nil {
				if memory.Max == nil {
					err = fmt.Errorf("incompatible memory imports: maximum size mismatch")
					return
				} else if *memory.Max > *memoryType.Max {
					err = fmt.Errorf("incompatible memory imports: maximum size mismatch")
					return
				}
			}
		case ExternTypeGlobal:
			globalType := is.DescGlobal
			if globalType == nil {
				err = fmt.Errorf("global type is invalid")
				return
			}
			g := exp.Global
			if globalType.Mutable != g.Type.Mutable {
				err = fmt.Errorf("incompatible global import: mutability mismatch")
				return
			} else if globalType.ValType != g.Type.ValType {
				err = fmt.Errorf("incompatible global import: value type mismatch")
				return
			}
			globals = append(globals, g)
		}
	}
	return
}

func executeConstExpression(globals []*GlobalInstance, expr *ConstantExpression) (v interface{}) {
	r := bytes.NewBuffer(expr.Data)
	switch expr.Opcode {
	case OpcodeI32Const:
		v, _, _ = leb128.DecodeInt32(r)
	case OpcodeI64Const:
		v, _, _ = leb128.DecodeInt64(r)
	case OpcodeF32Const:
		v, _ = ieee754.DecodeFloat32(r)
	case OpcodeF64Const:
		v, _ = ieee754.DecodeFloat64(r)
	case OpcodeGlobalGet:
		id, _, _ := leb128.DecodeUint32(r)
		g := globals[id]
		switch g.Type.ValType {
		case ValueTypeI32:
			v = int32(g.Val)
		case ValueTypeI64:
			v = int64(g.Val)
		case ValueTypeF32:
			v = publicwasm.DecodeF32(g.Val)
		case ValueTypeF64:
			v = publicwasm.DecodeF64(g.Val)
		}
	}
	return
}

func (m *ModuleInstance) validateData(module *Module) (err error) {
	for _, d := range module.DataSection {
		offset := uint64(executeConstExpression(m.Globals, d.OffsetExpression).(int32))

		size := offset + uint64(len(d.Init))
		maxPage := MemoryMaxPages
		if d.MemoryIndex < module.SectionElementCount(SectionIDMemory) && module.MemorySection[d.MemoryIndex].Max != nil {
			maxPage = *module.MemorySection[d.MemoryIndex].Max
		}
		if size > memoryPagesToBytesNum(maxPage) {
			return fmt.Errorf("memory size out of limit %d * 64Ki", int(*(module.MemorySection[d.MemoryIndex].Max)))
		}

		if size > uint64(len(m.MemoryInstance.Buffer)) {
			return fmt.Errorf("out of bounds memory access")
		}
	}
	return
}

func (m *ModuleInstance) applyData(data []*DataSegment) {
	for _, d := range data {
		offset := uint64(executeConstExpression(m.Globals, d.OffsetExpression).(int32))
		copy(m.MemoryInstance.Buffer[offset:], d.Init)
	}
}

func (m *ModuleInstance) validateElements(module *Module) (err error) {
	for _, elem := range module.ElementSection {
		if elem.TableIndex >= Index(len(m.Tables)) {
			return fmt.Errorf("index out of range of index space")
		}

		offset := int(executeConstExpression(m.Globals, elem.OffsetExpr).(int32))
		ceil := offset + len(elem.Init)

		max := uint32(math.MaxUint32)
		if elem.TableIndex < module.SectionElementCount(SectionIDTable) && module.TableSection[elem.TableIndex].Limit.Max != nil {
			max = *module.TableSection[elem.TableIndex].Limit.Max
		}

		if ceil > int(max) {
			return fmt.Errorf("table size out of limit of %d", max)
		}

		tableInst := m.Tables[elem.TableIndex]
		if ceil > len(tableInst.Table) {
			return fmt.Errorf("out of bounds table access %d > %v", ceil, len(tableInst.Table))
		}
		for i := range elem.Init {
			i := i
			elm := elem.Init[i]
			if elm >= uint32(len(m.Functions)) {
				return fmt.Errorf("unknown function specified by element")
			}
		}
	}
	return
}

func (m *ModuleInstance) applyElements(elements []*ElementSegment) (err error) {
	for _, elem := range elements {
		offset := int(executeConstExpression(m.Globals, elem.OffsetExpr).(int32))
		tableInst := m.Tables[elem.TableIndex]
		for i := range elem.Init {
			i := i
			elm := elem.Init[i]

			// Setup the rollback function before mutating the table instance.
			pos := i + offset
			targetFunc := m.Functions[elm]
			tableInst.Table[pos] = TableElement{
				FunctionAddress: targetFunc.Address,
				FunctionTypeID:  targetFunc.FunctionType.TypeID,
			}
		}
	}
	return
}

func (m *ModuleInstance) buildExportInstances(module *Module) {
	m.Exports = make(map[string]*ExportInstance, module.SectionElementCount(SectionIDExport))
	for _, exp := range module.ExportSection {
		index := exp.Index
		var ei *ExportInstance
		switch exp.Type {
		case ExternTypeFunc:
			ei = &ExportInstance{Type: exp.Type, Function: m.Functions[index]}
			// The module instance of the host function is a fake that only includes the function and its types.
			// We need to assign the ModuleInstance when re-exporting so that any memory defined in the target is
			// available to the wasm.ModuleContext Memory.
			if ei.Function.HostFunction != nil {
				ei.Function.ModuleInstance = m
			}
		case ExternTypeGlobal:
			ei = &ExportInstance{Type: exp.Type, Global: m.Globals[index]}
		case ExternTypeMemory:
			ei = &ExportInstance{Type: exp.Type, Memory: m.MemoryInstance}
		case ExternTypeTable:
			ei = &ExportInstance{Type: exp.Type, Table: m.Tables[index]}
		}

		// We already validate the duplicates during module validation phase.
		_ = m.addExport(exp.Name, ei)
	}
}

// DecodeBlockType is exported for use in the compiler
func DecodeBlockType(types []*FunctionType, r io.Reader) (*FunctionType, uint64, error) {
	return decodeBlockTypeImpl(func(index int64) (*FunctionType, error) {
		if index < 0 || (index >= int64(len(types))) {
			return nil, fmt.Errorf("invalid block type: %d", index)
		}
		return types[index], nil
	}, r)
}

// DecodeBlockType is exported for use in the compiler
func DecodeBlockTypeFromTypeInstances(types []*TypeInstance, r io.Reader) (*FunctionType, uint64, error) {
	return decodeBlockTypeImpl(func(index int64) (*FunctionType, error) {
		if index < 0 || (index >= int64(len(types))) {
			return nil, fmt.Errorf("invalid block type: %d", index)
		}
		return types[index].Type, nil
	}, r)
}

func decodeBlockTypeImpl(functionTypeResolver func(index int64) (*FunctionType, error), r io.Reader) (*FunctionType, uint64, error) {
	raw, num, err := leb128.DecodeInt33AsInt64(r)
	if err != nil {
		return nil, 0, fmt.Errorf("decode int33: %w", err)
	}

	var ret *FunctionType
	switch raw {
	case -64: // 0x40 in original byte = nil
		ret = &FunctionType{}
	case -1: // 0x7f in original byte = i32
		ret = &FunctionType{Results: []ValueType{ValueTypeI32}}
	case -2: // 0x7e in original byte = i64
		ret = &FunctionType{Results: []ValueType{ValueTypeI64}}
	case -3: // 0x7d in original byte = f32
		ret = &FunctionType{Results: []ValueType{ValueTypeF32}}
	case -4: // 0x7c in original byte = f64
		ret = &FunctionType{Results: []ValueType{ValueTypeF64}}
	default:
		ret, err = functionTypeResolver(raw)
	}
	return ret, num, err
}

// AddHostFunction exports a function so that it can be imported under the given module and name. If a function already
// exists for this module and name it is ignored rather than overwritten.
//
// Note: The wasm.Memory of the fn will be from the importing module.
func (s *Store) AddHostFunction(m *ModuleInstance, hf *GoFunc) (*FunctionInstance, error) {
	typeInstance, err := s.getTypeInstance(hf.functionType)
	if err != nil {
		return nil, err
	}

	f := &FunctionInstance{
		Name:           fmt.Sprintf("%s.%s", m.Name, hf.wasmFunctionName),
		HostFunction:   hf.goFunc,
		FunctionKind:   hf.functionKind,
		FunctionType:   typeInstance,
		ModuleInstance: m,
	}

	s.addFunctionInstances(f)

	if err = s.Engine.Compile(f); err != nil {
		if err := s.releaseFunctionInstances(f); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to compile %s: %v", f.Name, err)
	}

	if err = m.addExport(hf.wasmFunctionName, &ExportInstance{Type: ExternTypeFunc, Function: f}); err != nil {
		return nil, err
	}
	return f, nil
}

func (s *Store) AddGlobal(m *ModuleInstance, name string, value uint64, valueType ValueType, mutable bool) error {
	g := &GlobalInstance{
		Val:  value,
		Type: &GlobalType{Mutable: mutable, ValType: valueType},
	}
	s.addGlobalInstances(g)

	return m.addExport(name, &ExportInstance{Type: ExternTypeGlobal, Global: g})
}

func (s *Store) AddTableInstance(m *ModuleInstance, name string, min uint32, max *uint32) error {
	t := newTableInstance(min, max)
	s.addTableInstances(t)

	return m.addExport(name, &ExportInstance{Type: ExternTypeTable, Table: t})
}

func (s *Store) AddMemoryInstance(m *ModuleInstance, name string, min uint32, max *uint32) error {
	memory := &MemoryInstance{
		Buffer: make([]byte, memoryPagesToBytesNum(min)),
		Min:    min,
		Max:    max,
	}
	s.addMemoryInstance(memory)

	return m.addExport(name, &ExportInstance{Type: ExternTypeMemory, Memory: memory})
}

func (s *Store) getTypeInstances(ts []*FunctionType) ([]*TypeInstance, error) {
	ret := make([]*TypeInstance, len(ts))
	for i, t := range ts {
		inst, err := s.getTypeInstance(t)
		if err != nil {
			return nil, err
		}
		ret[i] = inst
	}
	return ret, nil
}

func (s *Store) getTypeInstance(t *FunctionType) (*TypeInstance, error) {
	// TODO: take mutex
	key := t.String()
	id, ok := s.TypeIDs[key]
	if !ok {
		l := len(s.TypeIDs)
		if l >= s.maximumFunctionTypes {
			return nil, fmt.Errorf("too many function types in a store")
		}
		id = FunctionTypeID(len(s.TypeIDs))
		s.TypeIDs[key] = id
	}
	return &TypeInstance{Type: t, TypeID: id}, nil
}

func newTableInstance(min uint32, max *uint32) *TableInstance {
	tableInst := &TableInstance{
		Table:    make([]TableElement, min),
		Min:      min,
		Max:      max,
		ElemType: 0x70, // funcref
	}
	for i := range tableInst.Table {
		tableInst.Table[i] = TableElement{
			FunctionTypeID: UninitializedTableElementTypeID,
		}
	}
	return tableInst
}

// UninitializedTableElementTypeID math.MaxUint64 to represent the uninitialized elements.
var UninitializedTableElementTypeID FunctionTypeID = math.MaxUint32
